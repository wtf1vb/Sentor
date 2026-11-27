// Слайдерная капча VK — порт Go pwdttcore/captcha_v2_slider.go.
//
// Получение пазла (captchaNotRobot.getContent), скоринг перестановок плиток
// по швам (luma/RGB/текстовые зоны) и генерация «человеческого» курсора.
//
// Отклонения от Go:
//  - декодирование изображений: Go image/png+image/jpeg → крейт `image`
//    (нужен в Cargo.toml, см. отчёт);
//  - параллельный stage-2 скоринг: Go-горутины → std::thread::scope;
//  - context.Context не портирован (паузы — thread::sleep).

use std::collections::{HashMap, HashSet};
use std::io::Cursor;
use std::thread;
use std::time::Duration;

use base64::Engine;
use serde::Serialize;
use serde_json::Value;

use super::captcha::{
    rand_below, sleep_or_cancel, CaptchaError, CaptchaSession, CAPTCHA_V2_DEVICE_INFO,
};
use crate::logging::log_add;

pub struct SliderPuzzleV2 {
    pub image: PuzzleImage,
    pub size: i64,
    pub swaps: Vec<i64>,
    pub attempts: i64,
}

#[derive(Debug, Clone, Default)]
pub struct SliderGuessV2 {
    pub index: i64,
    pub swaps: Vec<i64>,
    pub score: i64,
    pub score_rgb: i64,
    pub score_luma: i64,
    pub score_text: f64,
    pub consensus_rank: i64,
}

// ═══════════════════════════════════════════════════
// Изображение пазла
// ═══════════════════════════════════════════════════

/// RGBA8-картинка (аналог Go image.Image: At(x, y) с нулевым цветом вне границ).
pub struct PuzzleImage {
    width: i64,
    height: i64,
    pixels: Vec<u8>,
}

impl PuzzleImage {
    pub fn from_rgba8(img: ::image::RgbaImage) -> Self {
        let width = img.width() as i64;
        let height = img.height() as i64;
        PuzzleImage { width, height, pixels: img.into_raw() }
    }

    pub fn width(&self) -> i64 {
        self.width
    }

    pub fn height(&self) -> i64 {
        self.height
    }

    /// Go img.At(sx, sy): вне границ — прозрачный нулевой цвет.
    #[inline]
    pub fn at(&self, x: i64, y: i64) -> [u8; 4] {
        if x < 0 || y < 0 || x >= self.width || y >= self.height {
            return [0, 0, 0, 0];
        }
        let i = ((y * self.width + x) * 4) as usize;
        [self.pixels[i], self.pixels[i + 1], self.pixels[i + 2], self.pixels[i + 3]]
    }
}

#[derive(Debug, Clone, Copy)]
struct Rect {
    min_x: i64,
    min_y: i64,
    max_x: i64,
    max_y: i64,
}

impl Rect {
    fn dx(&self) -> i64 {
        self.max_x - self.min_x
    }
    fn dy(&self) -> i64 {
        self.max_y - self.min_y
    }
}

impl CaptchaSession {
    pub fn solve_slider_captcha(
        &self,
        session_token: &str,
        browser_fp: &str,
        hash: &str,
        settings: &str,
        debug_info: &str,
    ) -> Result<String, CaptchaError> {
        let values: Vec<(String, String)> = vec![
            ("session_token".to_string(), session_token.to_string()),
            ("domain".to_string(), "vk.com".to_string()),
            ("adFp".to_string(), String::new()),
            ("access_token".to_string(), String::new()),
            ("captcha_settings".to_string(), settings.to_string()),
        ];

        let resp = self
            .captcha_request("captchaNotRobot.getContent", &values)
            .map_err(|e| CaptchaError::Msg(format!("slider getContent failed: {}", e)))?;
        let puzzle = parse_slider_puzzle_v2(&resp)?;
        log_add(
            "wdtt",
            &format!(
                "[КАПЧА] v2 slider puzzle decoded: grid={} attempts={} swaps={}",
                puzzle.size,
                puzzle.attempts,
                puzzle.swaps.len()
            ),
        );

        let guesses = rank_slider_guesses_v2(&puzzle.image, puzzle.size, &puzzle.swaps)?;

        let mut limit = puzzle.attempts;
        if limit > guesses.len() as i64 {
            limit = guesses.len() as i64;
        }
        if limit <= 0 {
            return Err(CaptchaError::Msg("slider has no attempts available".to_string()));
        }
        log_add(
            "wdtt",
            &format!("[КАПЧА] v2 slider guesses ranked: total={} limit={}", guesses.len(), limit),
        );

        let mut device_json = CAPTCHA_V2_DEVICE_INFO.to_string();
        if let Some(sp) = &self.saved_profile {
            let trimmed = sp.device_json.trim();
            if !trimmed.is_empty() {
                device_json = trimmed.to_string();
            }
        }
        self.captcha_request(
            "captchaNotRobot.componentDone",
            &[
                ("session_token".to_string(), session_token.to_string()),
                ("domain".to_string(), "vk.com".to_string()),
                ("adFp".to_string(), String::new()),
                ("access_token".to_string(), String::new()),
                ("browser_fp".to_string(), browser_fp.to_string()),
                ("device".to_string(), device_json),
            ],
        )
        .map_err(|e| CaptchaError::Msg(format!("captcha componentDone failed: {}", e)))?;

        for i in 0..limit {
            if i > 0 {
                // человеческая пауза между попытками: раньше все проверки шли
                // назад-в-спину по мере ответов сервера — временной профиль
                // выдавал автоматизацию на самом «дорогом» пути
                if !sleep_or_cancel(
                    Duration::from_millis((400 + rand_below(250)) as u64),
                    &self.cancel,
                ) {
                    return Err(CaptchaError::Msg("context canceled".to_string()));
                }
            }
            let guess = &guesses[i as usize];
            log_add(
                "wdtt",
                &format!("[КАПЧА] v2 slider attempt {}/{} (guess #{})", i + 1, limit, guess.index),
            );
            let answer_data = serde_json::json!({ "value": guess.swaps }).to_string();
            let check = self.perform_captcha_check(
                session_token,
                browser_fp,
                hash,
                &answer_data,
                &build_slider_cursor_v2(guess.index, guesses.len() as i64),
                debug_info,
            )?;
            if check.status.eq_ignore_ascii_case("ok") {
                if check.success_token.is_empty() {
                    return Err(CaptchaError::Msg("captcha success token not found".to_string()));
                }
                log_add("wdtt", &format!("[КАПЧА] v2 slider accepted on attempt {}", i + 1));
                return Ok(check.success_token);
            }
            if check.status.eq_ignore_ascii_case("error_limit") {
                return Err(CaptchaError::RateLimit);
            }
            // сервер может сменить тип капчи (как в checkbox-пути) — раньше смена
            // типа молча проглатывалась, и цикл сжигал все попытки впустую
            if !check.show_type.is_empty() && !check.show_type.eq_ignore_ascii_case("slider") {
                return Err(CaptchaError::ShowType { show_type: check.show_type });
            }
        }
        Err(CaptchaError::Msg("slider guesses exhausted".to_string()))
    }
}

fn parse_slider_puzzle_v2(raw: &Value) -> Result<SliderPuzzleV2, CaptchaError> {
    let resp = raw
        .get("response")
        .and_then(|v| v.as_object())
        .ok_or_else(|| CaptchaError::Msg(format!("invalid slider content response: {}", raw)))?;
    let status = super::captcha::captcha_v2_stringify_any(resp.get("status").unwrap_or(&Value::Null));
    if !status.eq_ignore_ascii_case("ok") {
        return Err(CaptchaError::Msg(format!("slider getContent status: {}", status)));
    }
    let raw_image = super::captcha::captcha_v2_stringify_any(resp.get("image").unwrap_or(&Value::Null));
    if raw_image.is_empty() {
        return Err(CaptchaError::Msg("slider image missing".to_string()));
    }
    let raw_steps = resp
        .get("steps")
        .and_then(|v| v.as_array())
        .ok_or_else(|| CaptchaError::Msg("slider steps missing".to_string()))?;
    let mut steps: Vec<i64> = Vec::with_capacity(raw_steps.len());
    for item in raw_steps {
        match item {
            Value::Number(n) => steps.push(n.as_f64().unwrap_or(0.0) as i64),
            Value::String(s) => match s.trim().parse::<i64>() {
                Ok(n) => steps.push(n),
                Err(_) => return Err(CaptchaError::Msg(format!("invalid numeric value: {}", s))),
            },
            other => return Err(CaptchaError::Msg(format!("invalid numeric value: {}", other))),
        }
    }
    let (size, swaps, attempts) = split_slider_steps_v2(&steps)?;
    let data = base64::engine::general_purpose::STANDARD
        .decode(raw_image.as_bytes())
        .map_err(|e| CaptchaError::Msg(format!("decode slider image: {}", e)))?;
    // PNG-«бомба» (маленький файл → сотни мегапикселей) раньше декодировалась
    // целиком до какого-либо скоринга — сначала читаем только заголовки
    let (cfg_w, cfg_h) = ::image::ImageReader::new(Cursor::new(&data))
        .with_guessed_format()
        .map_err(|e| CaptchaError::Msg(format!("decode slider image config: {}", e)))?
        .into_dimensions()
        .map_err(|e| CaptchaError::Msg(format!("decode slider image config: {}", e)))?;
    if cfg_w == 0 || cfg_h == 0 || (cfg_w as u64) * (cfg_h as u64) > 8_000_000 {
        return Err(CaptchaError::Msg(format!("slider image rejected: {}x{}", cfg_w, cfg_h)));
    }
    let img = ::image::load_from_memory(&data)
        .map_err(|e| CaptchaError::Msg(format!("decode slider image: {}", e)))?
        .to_rgba8();
    Ok(SliderPuzzleV2 { image: PuzzleImage::from_rgba8(img), size, swaps, attempts })
}

fn split_slider_steps_v2(steps: &[i64]) -> Result<(i64, Vec<i64>, i64), CaptchaError> {
    if steps.len() < 3 {
        return Err(CaptchaError::Msg("slider steps payload too short".to_string()));
    }
    let size = steps[0];
    if size <= 0 {
        return Err(CaptchaError::Msg(format!("invalid slider size: {}", size)));
    }
    let mut tail = steps[1..].to_vec();
    let mut attempts = 4i64;
    if tail.len() % 2 != 0 {
        attempts = tail[tail.len() - 1];
        tail.pop();
        log_add(
            "wdtt",
            &format!("[КАПЧА] v2 slider payload had odd-length tail; fallback attempts={}", attempts),
        );
    }
    if attempts <= 0 {
        attempts = 4;
    }
    if tail.is_empty() || tail.len() % 2 != 0 {
        return Err(CaptchaError::Msg("invalid slider swap payload".to_string()));
    }
    Ok((size, tail, attempts))
}

fn rank_slider_guesses_v2(
    img: &PuzzleImage,
    grid_size: i64,
    swaps: &[i64],
) -> Result<Vec<SliderGuessV2>, CaptchaError> {
    let candidate_count = swaps.len() as i64 / 2;
    if candidate_count == 0 {
        return Err(CaptchaError::Msg("slider has no candidates".to_string()));
    }
    // «steps» — данные сервера (CDN VK): без потолка тысячи свопов давали
    // тысячи кандидатов и минуты CPU-скоринга в одном потоке. Легитимный
    // слайдер ограничен десятками кандидатов; превышение = битая/враждебная
    // капча → честная ошибка попытки (их число ограничено attempts)
    if candidate_count > 200 {
        return Err(CaptchaError::Msg(format!("slider candidates too many: {}", candidate_count)));
    }
    // вырожденные размеры: при картинке меньше сетки часть плиток пустая,
    // выборка цвета уходит вне границ и скоринг считается по мусору
    if img.width() < grid_size || img.height() < grid_size {
        return Err(CaptchaError::Msg(format!(
            "slider image too small: {}x{} for grid {}",
            img.width(),
            img.height(),
            grid_size
        )));
    }

    let mut guesses: Vec<SliderGuessV2> = Vec::with_capacity(candidate_count as usize);
    for idx in 1..=candidate_count {
        let active = active_swaps_for_index_v2(swaps, idx);
        let mapping = apply_slider_swaps_v2(grid_size, &active)?;
        let score_luma = seam_score_luma_v2(img, grid_size, &mapping);
        guesses.push(SliderGuessV2 {
            index: idx,
            swaps: active,
            score: 0,
            score_rgb: 0,
            score_luma,
            score_text: 0.0,
            consensus_rank: 0,
        });
    }

    let mut luma_order = guesses.clone();
    luma_order.sort_by(|a, b| a.score_luma.cmp(&b.score_luma).then(a.index.cmp(&b.index)));
    let mut luma_rank: HashMap<i64, i64> = HashMap::with_capacity(candidate_count as usize);
    for (rank, g) in luma_order.iter().enumerate() {
        luma_rank.insert(g.index, rank as i64);
    }

    let stage2_count = candidate_count.min(12);
    let stage2_set: HashSet<i64> = luma_order.iter().take(stage2_count as usize).map(|g| g.index).collect();

    // stage-2 (RGB + текстовый скоринг) — как в Go, параллельно по ядрам
    let jobs: Vec<i64> = stage2_set.iter().copied().collect();
    let workers = thread::available_parallelism().map(|n| n.get()).unwrap_or(1).max(1);
    let workers = workers.min(jobs.len().max(1));
    let chunk_size = (jobs.len() + workers - 1) / workers.max(1);

    let results: Vec<Result<Vec<(i64, i64, f64)>, CaptchaError>> = thread::scope(|scope| {
        let handles: Vec<_> = jobs
            .chunks(chunk_size.max(1))
            .map(|chunk| {
                let guesses_ref = &guesses;
                scope.spawn(move || -> Result<Vec<(i64, i64, f64)>, CaptchaError> {
                    let mut out: Vec<(i64, i64, f64)> = Vec::with_capacity(chunk.len());
                    for &index in chunk {
                        let mapping = apply_slider_swaps_v2(
                            grid_size,
                            &guesses_ref[(index - 1) as usize].swaps,
                        )?;
                        let (rgb, text) = seam_score_rgb_text_v2(img, grid_size, &mapping);
                        out.push((index, rgb, text));
                    }
                    Ok(out)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap_or_else(|_| {
            Err(CaptchaError::Msg("slider stage2 worker panicked".to_string()))
        })).collect()
    });
    for r in results {
        for (index, rgb, text) in r? {
            let g = &mut guesses[(index - 1) as usize];
            g.score_rgb = rgb;
            g.score_text = text;
        }
    }

    let stage2: Vec<SliderGuessV2> = guesses
        .iter()
        .filter(|g| stage2_set.contains(&g.index))
        .cloned()
        .collect();

    let mut rgb_order = stage2.clone();
    rgb_order.sort_by(|a, b| a.score_rgb.cmp(&b.score_rgb).then(a.index.cmp(&b.index)));
    let mut rgb_rank: HashMap<i64, i64> = HashMap::with_capacity(rgb_order.len());
    for (rank, g) in rgb_order.iter().enumerate() {
        rgb_rank.insert(g.index, rank as i64);
    }

    let mut text_order = stage2.clone();
    text_order.sort_by(|a, b| {
        a.score_text.partial_cmp(&b.score_text).unwrap_or(std::cmp::Ordering::Equal).then(a.index.cmp(&b.index))
    });
    let mut text_rank: HashMap<i64, i64> = HashMap::with_capacity(text_order.len());
    for (rank, g) in text_order.iter().enumerate() {
        text_rank.insert(g.index, rank as i64);
    }

    for g in guesses.iter_mut() {
        g.consensus_rank = *luma_rank.get(&g.index).unwrap_or(&0);
        if stage2_set.contains(&g.index) {
            g.consensus_rank += *rgb_rank.get(&g.index).unwrap_or(&0);
            g.consensus_rank += *text_rank.get(&g.index).unwrap_or(&0);
        } else {
            g.consensus_rank += candidate_count;
        }
        g.score = g.consensus_rank;
    }

    guesses.sort_by(|a, b| {
        a.consensus_rank
            .cmp(&b.consensus_rank)
            .then(a.score_luma.cmp(&b.score_luma))
            .then(a.index.cmp(&b.index))
    });
    Ok(guesses)
}

pub fn active_swaps_for_index_v2(swaps: &[i64], index: i64) -> Vec<i64> {
    if index <= 0 {
        return Vec::new();
    }
    let end = (index as usize * 2).min(swaps.len());
    swaps[..end].to_vec()
}

pub fn apply_slider_swaps_v2(grid_size: i64, swaps: &[i64]) -> Result<Vec<i64>, CaptchaError> {
    let tile_count = grid_size * grid_size;
    if tile_count <= 0 {
        return Err(CaptchaError::Msg(format!("invalid slider tile count: {}", tile_count)));
    }
    if swaps.len() % 2 != 0 {
        return Err(CaptchaError::Msg(format!("invalid slider swaps length: {}", swaps.len())));
    }
    let mut mapping: Vec<i64> = (0..tile_count).collect();
    for pair in swaps.chunks(2) {
        let left = pair[0];
        let right = pair[1];
        if left < 0 || right < 0 || left >= tile_count || right >= tile_count {
            return Err(CaptchaError::Msg(format!("slider step out of range: {},{}", left, right)));
        }
        mapping.swap(left as usize, right as usize);
    }
    Ok(mapping)
}

fn slider_tile_rect(width: i64, height: i64, grid_size: i64, index: i64) -> Rect {
    let col = index % grid_size;
    let row = index / grid_size;
    Rect {
        min_x: (col * width) / grid_size,
        min_y: (row * height) / grid_size,
        max_x: ((col + 1) * width) / grid_size,
        max_y: ((row + 1) * height) / grid_size,
    }
}

// Go color.RGBA() возвращает 16-битные premultiplied-каналы, код сравнивает их
// старшие 8 бит (>>8) — для непрозрачных JPEG/PNG это просто 8-битные каналы.
fn pixel_diff(a: [u8; 4], b: [u8; 4]) -> i64 {
    let dr = (a[0] as i64 - b[0] as i64).abs();
    let dg = (a[1] as i64 - b[1] as i64).abs();
    let db = (a[2] as i64 - b[2] as i64).abs();
    dr + dg + db
}

fn seam_score_luma_v2(img: &PuzzleImage, grid_size: i64, mapping: &[i64]) -> i64 {
    let width = img.width();
    let height = img.height();
    let mut score: i64 = 0;
    for row in 0..grid_size {
        for col in 0..grid_size - 1 {
            let left_idx = row * grid_size + col;
            let right_idx = left_idx + 1;
            let left_dst = slider_tile_rect(width, height, grid_size, left_idx);
            let right_dst = slider_tile_rect(width, height, grid_size, right_idx);
            let left_src = slider_tile_rect(width, height, grid_size, mapping[left_idx as usize]);
            let right_src = slider_tile_rect(width, height, grid_size, mapping[right_idx as usize]);
            let h = left_dst.dy().min(right_dst.dy());
            for y in 0..h {
                let yy = left_dst.min_y + y;
                let a = sample_luma_mapped_v2(img, &left_dst, &left_src, left_dst.max_x - 1, yy);
                let b = sample_luma_mapped_v2(img, &right_dst, &right_src, right_dst.min_x, yy);
                score += abs_int_v2(a as i64 - b as i64);
            }
        }
    }
    for row in 0..grid_size - 1 {
        for col in 0..grid_size {
            let top_idx = row * grid_size + col;
            let bottom_idx = (row + 1) * grid_size + col;
            let top_dst = slider_tile_rect(width, height, grid_size, top_idx);
            let bottom_dst = slider_tile_rect(width, height, grid_size, bottom_idx);
            let top_src = slider_tile_rect(width, height, grid_size, mapping[top_idx as usize]);
            let bottom_src = slider_tile_rect(width, height, grid_size, mapping[bottom_idx as usize]);
            let w = top_dst.dx().min(bottom_dst.dx());
            for x in 0..w {
                let xx = top_dst.min_x + x;
                let a = sample_luma_mapped_v2(img, &top_dst, &top_src, xx, top_dst.max_y - 1);
                let b = sample_luma_mapped_v2(img, &bottom_dst, &bottom_src, xx, bottom_dst.min_y);
                score += abs_int_v2(a as i64 - b as i64);
            }
        }
    }
    score
}

fn seam_score_rgb_text_v2(img: &PuzzleImage, grid_size: i64, mapping: &[i64]) -> (i64, f64) {
    let width = img.width();
    let height = img.height();
    let text_centers = [
        0.2 * height as f64,
        0.5 * height as f64,
        0.8 * height as f64,
    ];
    let mut sigma = height as f64 * 0.14;
    if sigma < 1.0 {
        sigma = 1.0;
    }
    let weight = |y: i64| -> f64 {
        let yf = y as f64;
        let mut best = abs_float_v2(yf - text_centers[0]);
        for center in text_centers.iter().skip(1) {
            let d = abs_float_v2(yf - center);
            if d < best {
                best = d;
            }
        }
        1.0 + 3.0 * (-(best * best) / (2.0 * sigma * sigma)).exp()
    };

    let mut rgb_score: i64 = 0;
    let mut text_score: f64 = 0.0;
    for row in 0..grid_size {
        for col in 0..grid_size - 1 {
            let left_idx = row * grid_size + col;
            let right_idx = left_idx + 1;
            let left_dst = slider_tile_rect(width, height, grid_size, left_idx);
            let right_dst = slider_tile_rect(width, height, grid_size, right_idx);
            let left_src = slider_tile_rect(width, height, grid_size, mapping[left_idx as usize]);
            let right_src = slider_tile_rect(width, height, grid_size, mapping[right_idx as usize]);
            let h = left_dst.dy().min(right_dst.dy());
            for y in 0..h {
                let yy = left_dst.min_y + y;
                let l = sample_color_mapped_v2(img, &left_dst, &left_src, left_dst.max_x - 1, yy);
                let r = sample_color_mapped_v2(img, &right_dst, &right_src, right_dst.min_x, yy);
                rgb_score += pixel_diff(l, r);
                // Go сравнивает синий канал (b>>8)
                text_score += weight(yy) * abs_int_v2(l[2] as i64 - r[2] as i64) as f64;
            }
        }
    }
    for row in 0..grid_size - 1 {
        for col in 0..grid_size {
            let top_idx = row * grid_size + col;
            let bottom_idx = (row + 1) * grid_size + col;
            let top_dst = slider_tile_rect(width, height, grid_size, top_idx);
            let bottom_dst = slider_tile_rect(width, height, grid_size, bottom_idx);
            let top_src = slider_tile_rect(width, height, grid_size, mapping[top_idx as usize]);
            let bottom_src = slider_tile_rect(width, height, grid_size, mapping[bottom_idx as usize]);
            let w = top_dst.dx().min(bottom_dst.dx());
            for x in 0..w {
                let xx = top_dst.min_x + x;
                let t = sample_color_mapped_v2(img, &top_dst, &top_src, xx, top_dst.max_y - 1);
                let b = sample_color_mapped_v2(img, &bottom_dst, &bottom_src, xx, bottom_dst.min_y);
                rgb_score += pixel_diff(t, b);
                text_score += 0.65 * abs_int_v2(t[2] as i64 - b[2] as i64) as f64;
            }
        }
    }
    (rgb_score, text_score)
}

fn sample_color_mapped_v2(
    img: &PuzzleImage,
    dst_rect: &Rect,
    src_rect: &Rect,
    dst_x: i64,
    dst_y: i64,
) -> [u8; 4] {
    let dx = dst_rect.dx().max(1);
    let dy = dst_rect.dy().max(1);
    let sx = src_rect.min_x + (dst_x - dst_rect.min_x) * src_rect.dx() / dx;
    let sy = src_rect.min_y + (dst_y - dst_rect.min_y) * src_rect.dy() / dy;
    img.at(sx, sy)
}

fn sample_luma_mapped_v2(
    img: &PuzzleImage,
    dst_rect: &Rect,
    src_rect: &Rect,
    dst_x: i64,
    dst_y: i64,
) -> u8 {
    let c = sample_color_mapped_v2(img, dst_rect, src_rect, dst_x, dst_y);
    // y := (299*(r>>8) + 587*(g>>8) + 114*(b>>8)) / 1000
    let y = (299 * c[0] as i64 + 587 * c[1] as i64 + 114 * c[2] as i64) / 1000;
    y as u8
}

fn abs_float_v2(v: f64) -> f64 {
    if v < 0.0 {
        -v
    } else {
        v
    }
}

fn abs_int_v2(v: i64) -> i64 {
    if v < 0 {
        -v
    } else {
        v
    }
}

#[derive(Serialize, Clone, Copy)]
struct CursorPoint {
    x: i64,
    y: i64,
}

pub fn build_slider_cursor_v2(candidate_index: i64, candidate_count: i64) -> String {
    if candidate_count <= 0 {
        return "[]".to_string();
    }
    let mut candidate_index = candidate_index;
    if candidate_index < 1 {
        candidate_index = 1;
    }
    if candidate_index > candidate_count {
        candidate_index = candidate_count;
    }

    let start_x = 570 + rand_below(40);
    let start_y = 875 + rand_below(30);

    let mut denom = candidate_count - 1;
    if denom < 1 {
        denom = 1;
    }
    let base_target_x = 734 + (937 - 734) * (candidate_index - 1) / denom;
    let target_x = base_target_x + rand_below(10) - 5;
    let target_y = 655 + rand_below(14);

    let mut points: Vec<CursorPoint> = Vec::with_capacity(28);

    for _ in 0..1 + rand_below(3) {
        points.push(CursorPoint {
            x: start_x + rand_below(5) - 2,
            y: start_y + rand_below(5) - 2,
        });
    }

    let transit_steps = 2 + rand_below(3);
    let arc_off_x = rand_below(60) - 30;
    let arc_off_y = -(rand_below(30) + 10);
    for i in 1..=transit_steps {
        let t = i as f64 / (transit_steps + 1) as f64;
        let cx = (start_x + target_x) as f64 / 2.0 + arc_off_x as f64;
        let cy = (start_y + target_y) as f64 / 2.0 + arc_off_y as f64;
        let bx = (1.0 - t) * (1.0 - t) * start_x as f64 + 2.0 * t * (1.0 - t) * cx + t * t * target_x as f64;
        let by = (1.0 - t) * (1.0 - t) * start_y as f64 + 2.0 * t * (1.0 - t) * cy + t * t * target_y as f64;
        let jitter = ((1.0 - t) * 8.0) as i64 + 2;
        points.push(CursorPoint {
            x: bx.round() as i64 + rand_below(jitter * 2 + 1) - jitter,
            y: by.round() as i64 + rand_below(jitter * 2 + 1) - jitter,
        });
    }

    let approach_steps = 4 + rand_below(4);
    let prev = points[points.len() - 1];
    for i in 1..=approach_steps {
        let t = i as f64 / approach_steps as f64;
        let ax = prev.x + (t * (target_x - prev.x) as f64).round() as i64 + rand_below(5) - 2;
        let ay = prev.y + (t * (target_y - prev.y) as f64).round() as i64 + rand_below(5) - 2;
        points.push(CursorPoint { x: ax, y: ay });
    }

    let settle_count = 3 + rand_below(5);
    for _ in 0..settle_count {
        points.push(CursorPoint {
            x: target_x + rand_below(7) - 3,
            y: target_y + rand_below(7) - 3,
        });
    }

    serde_json::to_string(&points).unwrap_or_else(|_| "[]".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_slider_steps() {
        let (size, swaps, attempts) = split_slider_steps_v2(&[3, 0, 1, 1, 2]).unwrap();
        assert_eq!(size, 3);
        assert_eq!(swaps, vec![0, 1, 1, 2]);
        assert_eq!(attempts, 4);
    }

    #[test]
    fn test_split_slider_steps_odd_tail() {
        let (size, swaps, attempts) = split_slider_steps_v2(&[3, 0, 1, 1, 2, 7]).unwrap();
        assert_eq!(size, 3);
        assert_eq!(swaps, vec![0, 1, 1, 2]);
        assert_eq!(attempts, 7);
    }

    #[test]
    fn test_split_slider_steps_too_short() {
        assert!(split_slider_steps_v2(&[3, 0]).is_err());
    }

    #[test]
    fn test_apply_slider_swaps() {
        assert_eq!(apply_slider_swaps_v2(2, &[0, 1]).unwrap(), vec![1, 0, 2, 3]);
        assert!(apply_slider_swaps_v2(2, &[0, 9]).is_err());
        assert!(apply_slider_swaps_v2(2, &[0]).is_err());
    }

    #[test]
    fn test_active_swaps_for_index() {
        let swaps = [1, 2, 3, 4, 5, 6];
        assert!(active_swaps_for_index_v2(&swaps, 0).is_empty());
        assert_eq!(active_swaps_for_index_v2(&swaps, 1), vec![1, 2]);
        assert_eq!(active_swaps_for_index_v2(&swaps, 3), vec![1, 2, 3, 4, 5, 6]);
        assert_eq!(active_swaps_for_index_v2(&swaps, 10), vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_build_slider_cursor() {
        let cursor = build_slider_cursor_v2(1, 5);
        let parsed: Value = serde_json::from_str(&cursor).unwrap();
        assert!(parsed.as_array().unwrap().len() > 0);
        assert_eq!(build_slider_cursor_v2(1, 0), "[]");
    }

    #[test]
    fn test_pixel_diff_and_luma() {
        assert_eq!(pixel_diff([10, 20, 30, 255], [10, 25, 28, 255]), 7);
        // (299*0 + 587*255 + 114*0) / 1000 = 149
        let img_data = vec![0u8, 255, 0, 255];
        let img = PuzzleImage { width: 1, height: 1, pixels: img_data };
        assert_eq!(img.at(0, 0), [0, 255, 0, 255]);
        assert_eq!(img.at(5, 5), [0, 0, 0, 0]);
    }
}
