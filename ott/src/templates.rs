//! minijinja environment setup.
//!
//! Templates live in `templates/*.html.j2` and are embedded into the
//! binary via [`rust_embed`]. The `.j2` extension is stripped during
//! registration so `{% extends "base.html" %}` in a template resolves
//! by the friendly name.

use minijinja::Environment;
use rust_embed::Embed;

/// All `templates/*` files embedded at compile time.
#[derive(Embed)]
#[folder = "templates/"]
pub struct Templates;

/// Build the application's minijinja environment with every embedded
/// template registered.
///
/// Each file's path is registered minus its trailing `.j2` extension,
/// so `templates/home.html.j2` becomes the template named
/// `home.html`.
pub fn environment() -> Environment<'static> {
    let mut env = Environment::new();
    for path in Templates::iter() {
        let file = Templates::get(path.as_ref())
            .expect("rust_embed::iter yields keys that get() resolves");
        let body = std::str::from_utf8(file.data.as_ref()).expect("template files are UTF-8");
        let name = path
            .strip_suffix(".j2")
            .map(|n| n.to_owned())
            .unwrap_or_else(|| path.to_string());
        env.add_template_owned(name, body.to_owned())
            .expect("embedded template compiles");
    }
    env
}

#[cfg(test)]
mod tests {
    use super::*;
    use minijinja::context;

    #[test]
    fn registers_every_embedded_template() {
        let env = environment();
        // Should at minimum have the three Phase B templates.
        for name in ["base.html", "home.html", "profile.html"] {
            assert!(
                env.get_template(name).is_ok(),
                "template {name} should be registered",
            );
        }
    }

    #[test]
    fn home_renders_with_provider_name() {
        let env = environment();
        let tmpl = env.get_template("home.html").unwrap();
        let body = tmpl
            .render(context! {
                provider_name => "Google",
                redirect_uri => "http://127.0.0.1:3000/auth/callback",
            })
            .unwrap();
        assert!(body.contains("Sign in with Google"));
        assert!(body.contains("/auth/login"));
    }

    #[test]
    fn profile_renders_user_card() {
        let env = environment();
        let tmpl = env.get_template("profile.html").unwrap();
        let body = tmpl
            .render(context! {
                user => context! {
                    sub => "abc123",
                    email => "alice@example.com",
                    email_verified => true,
                    display_name => "Alice",
                    created_at => "2026-05-18T00:00:00Z",
                    last_login_at => "2026-05-18T00:00:00Z",
                },
                user_json => "{\"sub\":\"abc123\"}",
            })
            .unwrap();
        assert!(body.contains("Signed in as Alice"));
        assert!(body.contains("alice@example.com"));
        assert!(body.contains("verified"));
        assert!(body.contains("Sign out"));
    }
}
