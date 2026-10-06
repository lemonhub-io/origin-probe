use serde::Serialize;

/// Order here is the order sections appear in the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Category {
    System,
    Locale,
    Input,
    Fonts,
    Software,
    Mirrors,
    Identity,
    Network,
}

impl Category {
    pub const ALL: [Category; 8] = [
        Category::System,
        Category::Locale,
        Category::Input,
        Category::Fonts,
        Category::Software,
        Category::Mirrors,
        Category::Identity,
        Category::Network,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Category::System => "System & Hardware",
            Category::Locale => "Locale & Timezone",
            Category::Input => "Input Methods",
            Category::Fonts => "Fonts",
            Category::Software => "Installed Software",
            Category::Mirrors => "Package Mirrors",
            Category::Identity => "User Identity & Habits",
            Category::Network => "Network & Location",
        }
    }
}

/// One row of collected evidence. `lr` is the likelihood ratio for the
/// hypothesis "the device user is Chinese": >1 supports it, <1 argues
/// against it, exactly 1.0 means "neutral fact shown for context only".
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    #[serde(serialize_with = "ser_cat")]
    pub category: Category,
    /// What was probed, e.g. "LANG" or "TCP www.youtube.com:443".
    pub name: String,
    /// The observed value.
    pub observed: String,
    pub lr: f64,
    /// True when the signal points specifically at mainland China rather
    /// than the broader Chinese-speaking world (TW/HK/SG/diaspora).
    pub mainland: bool,
    pub note: String,
}

fn ser_cat<S: serde::Serializer>(c: &Category, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(c.title())
}

impl Finding {
    /// A display-only row (lr = 1.0, contributes nothing to the score).
    pub fn fact(category: Category, name: impl Into<String>, observed: impl Into<String>) -> Self {
        Finding {
            category,
            name: name.into(),
            observed: observed.into(),
            lr: 1.0,
            mainland: false,
            note: String::new(),
        }
    }

    /// A scored evidence row.
    pub fn signal(
        category: Category,
        name: impl Into<String>,
        observed: impl Into<String>,
        lr: f64,
        mainland: bool,
        note: impl Into<String>,
    ) -> Self {
        Finding {
            category,
            name: name.into(),
            observed: observed.into(),
            lr,
            mainland,
            note: note.into(),
        }
    }
}
