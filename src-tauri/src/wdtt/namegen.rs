// Порт Go namegen.go: генерация случайных русских имён для устройств.
static MALE_FIRST_NAMES: &[&str] = &[
    "Александр", "Алексей", "Андрей", "Антон", "Арсений",
    "Артур", "Артём", "Богдан", "Валерий", "Василий",
    "Виктор", "Владислав", "Глеб", "Григорий", "Даниил",
    "Денис", "Дмитрий", "Евгений", "Егор", "Иван",
    "Игорь", "Илья", "Кирилл", "Леонид", "Максим",
    "Марк", "Матвей", "Михаил", "Никита", "Николай",
    "Олег", "Павел", "Пётр", "Роман", "Руслан",
    "Сергей", "Станислав", "Тимофей", "Фёдор",
];

static FEMALE_FIRST_NAMES: &[&str] = &[
    "Алина", "Алёна", "Анастасия", "Ангелина", "Анна",
    "Вера", "Вероника", "Виктория", "Дарья", "Ева",
    "Екатерина", "Елена", "Елизавета", "Ирина", "Кира",
    "Кристина", "Ксения", "Любовь", "Маргарита", "Марина",
    "Мария", "Милана", "Надежда", "Наталья", "Ольга",
    "Полина", "Светлана", "София", "Татьяна", "Юлия", "Яна",
];

static LAST_NAMES: &[&str] = &[
    "Алексеев", "Андреев", "Антонов", "Баранов", "Белов",
    "Белый", "Бельский", "Беляев", "Борисов", "Васильев",
    "Великий", "Волков", "Воробьёв", "Григорьев", "Давыдов",
    "Егоров", "Жуков", "Зайцев", "Захаров", "Иванов",
    "Калинин", "Ковалёв", "Козлов", "Комаров", "Крамской",
    "Кузнецов", "Кузьмин", "Лебедев", "Макаров", "Медведев",
    "Михайлов", "Морозов", "Никитин", "Николаев", "Новиков",
    "Орлов", "Островский", "Павлов", "Петров", "Покровский",
    "Попов", "Раевский", "Романов", "Семёнов", "Сергеев",
    "Смирнов", "Соколов", "Соловьёв", "Степанов", "Тарасов",
    "Титов", "Толстой", "Трубецкой", "Филиппов", "Фролов",
    "Фёдоров", "Чайковский", "Черный", "Яковлев",
];

// Go: func convertToFemaleSurname(surname string) string
fn convert_to_female_surname(surname: &str) -> String {
    if surname.ends_with("ий") || surname.ends_with("ый") || surname.ends_with("ой") {
        // Go: surname[:len(surname)-4] + "ая" (2 кириллических символа = 4 байта)
        return format!("{}ая", &surname[..surname.len() - 4]);
    }
    if surname.ends_with("ов")
        || surname.ends_with("ев")
        || surname.ends_with("ин")
        || surname.ends_with("ын")
        || surname.ends_with("ёв")
    {
        return format!("{}а", surname);
    }
    surname.to_string()
}

// Go: func generateName() string
pub fn generate_name() -> String {
    let is_female = fastrand::usize(..2) == 0;
    let first_name = if is_female {
        FEMALE_FIRST_NAMES[fastrand::usize(..FEMALE_FIRST_NAMES.len())]
    } else {
        MALE_FIRST_NAMES[fastrand::usize(..MALE_FIRST_NAMES.len())]
    };

    if fastrand::f32() < 0.3 {
        return first_name.to_string();
    }
    let last = LAST_NAMES[fastrand::usize(..LAST_NAMES.len())];
    let last_name = if is_female {
        convert_to_female_surname(last)
    } else {
        last.to_string()
    };
    format!("{} {}", first_name, last_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn female_surname_forms() {
        assert_eq!(convert_to_female_surname("Алексеев"), "Алексеева");
        assert_eq!(convert_to_female_surname("Фёдоров"), "Фёдорова");
        assert_eq!(convert_to_female_surname("Ковалёв"), "Ковалёва");
        assert_eq!(convert_to_female_surname("Иванов"), "Иванова");
        assert_eq!(convert_to_female_surname("Белый"), "Белая");
        assert_eq!(convert_to_female_surname("Великий"), "Великая");
        assert_eq!(convert_to_female_surname("Крамской"), "Крамская");
        assert_eq!(convert_to_female_surname("Трубецкой"), "Трубецкая");
        assert_eq!(convert_to_female_surname("Черный"), "Черная"); // «ый» → «ая»
    }

    #[test]
    fn generated_names_are_sane() {
        for _ in 0..500 {
            let n = generate_name();
            assert!(!n.is_empty());
            assert!(n.chars().all(|c| c.is_alphanumeric() || c == ' ' || c == '-'));
        }
    }
}
