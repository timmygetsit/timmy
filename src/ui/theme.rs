use ratatui::style::{Color, Modifier, Style};

/// Visual theme and styling for TIMMY TUI.
pub struct Theme {
    pub primary: Color,
    pub secondary: Color,
    pub highlight: Color,
    pub warning: Color,
    pub danger: Color,
    pub success: Color,
    pub muted: Color,
    pub bg_dark: Color,
}

impl Theme {
    pub fn default_dark() -> Self {
        Self {
            primary: Color::Cyan,
            secondary: Color::Blue,
            highlight: Color::Yellow,
            warning: Color::Rgb(255, 165, 0),
            danger: Color::Red,
            success: Color::Green,
            muted: Color::DarkGray,
            bg_dark: Color::Black,
        }
    }

    pub fn title_style(&self) -> Style {
        Style::default()
            .fg(self.primary)
            .add_modifier(Modifier::BOLD)
    }

    pub fn tab_active_style(&self) -> Style {
        Style::default()
            .fg(Color::Black)
            .bg(self.primary)
            .add_modifier(Modifier::BOLD)
    }

    pub fn tab_inactive_style(&self) -> Style {
        Style::default().fg(Color::Gray)
    }

    pub fn header_style(&self) -> Style {
        Style::default()
            .fg(Color::White)
            .bg(Color::Rgb(30, 30, 40))
            .add_modifier(Modifier::BOLD)
    }

    pub fn row_selected_style(&self) -> Style {
        Style::default()
            .fg(Color::Black)
            .bg(self.primary)
            .add_modifier(Modifier::BOLD)
    }

    pub fn confidence_style(&self, conf: crate::model::Confidence) -> Style {
        match conf {
            crate::model::Confidence::Confirmed => Style::default()
                .fg(self.success)
                .add_modifier(Modifier::BOLD),
            crate::model::Confidence::HighConfidence => Style::default()
                .fg(self.primary)
                .add_modifier(Modifier::BOLD),
            crate::model::Confidence::Inferred => Style::default().fg(self.highlight),
            crate::model::Confidence::Unknown => Style::default().fg(self.muted),
        }
    }
}
