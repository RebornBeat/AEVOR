use dialoguer::{Select, Confirm, Input, Password, Editor, MultiSelect, FuzzySelect, theme::ColorfulTheme};
use console::Term;

/// Get a custom theme for dialoguer
pub fn theme() -> ColorfulTheme {
    ColorfulTheme::default()
}

/// Prompt the user to select an option from a list
pub fn select<'a>(prompt: &str, options: &'a [&str]) -> Result<&'a str, String> {
    let selection = Select::with_theme(&theme())
        .with_prompt(prompt)
        .items(options)
        .default(0)
        .interact_on_opt(&Term::stderr())
        .map_err(|e| e.to_string())?;

    match selection {
        Some(index) => Ok(options[index]),
        None => Err("Selection cancelled".to_string()),
    }
}

/// Prompt the user to select multiple options from a list
pub fn multi_select<'a>(prompt: &str, options: &'a [&str]) -> Result<Vec<&'a str>, String> {
    let selection = MultiSelect::with_theme(&theme())
        .with_prompt(prompt)
        .items(options)
        .interact_on_opt(&Term::stderr())
        .map_err(|e| e.to_string())?;

    match selection {
        Some(indices) => Ok(indices.into_iter().map(|i| options[i]).collect()),
        None => Err("Selection cancelled".to_string()),
    }
}

/// Prompt the user to select an option from a list with fuzzy matching
pub fn fuzzy_select<'a>(prompt: &str, options: &'a [&str]) -> Result<&'a str, String> {
    let selection = FuzzySelect::with_theme(&theme())
        .with_prompt(prompt)
        .items(options)
        .default(0)
        .interact_on_opt(&Term::stderr())
        .map_err(|e| e.to_string())?;

    match selection {
        Some(index) => Ok(options[index]),
        None => Err("Selection cancelled".to_string()),
    }
}

/// Prompt the user for confirmation (yes/no)
pub fn confirm(prompt: &str) -> Result<bool, String> {
    Confirm::with_theme(&theme())
        .with_prompt(prompt)
        .default(false)
        .interact_on_opt(&Term::stderr())
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Confirmation cancelled".to_string())
}

/// Prompt the user for text input
pub fn input<T>(prompt: &str, default: Option<T>) -> Result<T, String>
where
    T: std::str::FromStr + std::string::ToString + Clone,
    T::Err: std::fmt::Display,
{
    let mut input = Input::with_theme(&theme())
        .with_prompt(prompt);
    
    if let Some(default_value) = default {
        input = input.default(default_value);
    }
    
    input.interact_on_opt(&Term::stderr())
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Input cancelled".to_string())
}

/// Prompt the user for a password
pub fn password(prompt: &str) -> Result<String, String> {
    Password::with_theme(&theme())
        .with_prompt(prompt)
        .interact_on_opt(&Term::stderr())
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Password input cancelled".to_string())
}

/// Prompt the user for a password with confirmation
pub fn password_with_confirmation(prompt: &str, confirm_prompt: &str) -> Result<String, String> {
    Password::with_theme(&theme())
        .with_prompt(prompt)
        .with_confirmation(confirm_prompt, "Passwords do not match")
        .interact_on_opt(&Term::stderr())
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Password input cancelled".to_string())
}

/// Prompt the user for multi-line input using an editor
pub fn editor(prompt: &str, initial: Option<&str>) -> Result<String, String> {
    let mut editor = Editor::new();
    
    if let Some(initial_text) = initial {
        editor = editor.editor_command("auto").text(initial_text);
    }
    
    editor.edit(prompt)
        .map_err(|e| e.to_string())
}

/// Prompt the user for a numeric input within a range
pub fn numeric_input<T>(prompt: &str, min: Option<T>, max: Option<T>, default: Option<T>) -> Result<T, String>
where
    T: std::str::FromStr + std::string::ToString + std::cmp::PartialOrd + Clone,
    T::Err: std::fmt::Display,
{
    let mut input = Input::with_theme(&theme())
        .with_prompt(prompt);
    
    if let Some(min_value) = min {
        if let Some(max_value) = max.clone() {
            input = input.validate_with(move |input: &T| -> Result<(), String> {
                if *input < min_value || *input > max_value {
                    Err(format!("Input must be between {} and {}", min_value.to_string(), max_value.to_string()))
                } else {
                    Ok(())
                }
            });
        } else {
            input = input.validate_with(move |input: &T| -> Result<(), String> {
                if *input < min_value {
                    Err(format!("Input must be at least {}", min_value.to_string()))
                } else {
                    Ok(())
                }
            });
        }
    } else if let Some(max_value) = max {
        input = input.validate_with(move |input: &T| -> Result<(), String> {
            if *input > max_value {
                Err(format!("Input must be at most {}", max_value.to_string()))
            } else {
                Ok(())
            }
        });
    }
    
    if let Some(default_value) = default {
        input = input.default(default_value);
    }
    
    input.interact_on_opt(&Term::stderr())
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Input cancelled".to_string())
}

/// Display a spinner while executing a function
pub fn with_spinner<F, T>(message: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    use indicatif::{ProgressBar, ProgressStyle};
    use std::time::Duration;
    
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&[
                "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"
            ])
            .template("{spinner:.purple} {msg:.bright_blue}")
            .unwrap()
    );
    spinner.set_message(message.to_string());
    spinner.enable_steady_tick(Duration::from_millis(100));
    
    let result = f();
    
    spinner.finish_with_message("Done!");
    
    result
}
