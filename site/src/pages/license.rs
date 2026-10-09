use yew::prelude::*;
use yew_router::prelude::*;

use crate::app::Route;
use crate::config::LICENSE_FILE;
use crate::prefs::use_prefs;

#[function_component(LicensePage)]
pub fn license_page() -> Html {
    let prefs = use_prefs();
    html! {
        <div class="container">
            <section class="legal">
                <h1>{ prefs.t("license.title") }</h1>
                <p class="legal-note">{ prefs.t("license.note") }</p>
                <pre class="license-text">{ prefs.t("license.full") }</pre>
                <p>
                    <a href={LICENSE_FILE} target="_blank" rel="noopener noreferrer">{ prefs.t("license.viewFile") }</a>
                </p>
                <p><Link<Route> to={Route::Home} classes="back">{ prefs.t("back") }</Link<Route>></p>
            </section>
        </div>
    }
}
