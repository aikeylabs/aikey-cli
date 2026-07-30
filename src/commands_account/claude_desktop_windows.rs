//! Windows-only Claude Desktop installation discovery.
//!
//! Microsoft Store/MSIX applications live under the protected WindowsApps
//! directory, but that physical path is not a stable or appropriate discovery
//! surface. Ask Windows for packages registered to the current user instead.

use windows::{core::HSTRING, Management::Deployment::PackageManager};

const CLAUDE_PACKAGE_NAME: &str = "Claude";

pub(super) fn is_claude_msix_registered_for_current_user() -> Result<bool, String> {
    let manager =
        PackageManager::new().map_err(|e| format!("create Windows PackageManager: {e}"))?;
    let packages = manager
        .FindPackagesByUserSecurityId(&HSTRING::new())
        .map_err(|e| format!("enumerate packages registered for the current user: {e}"))?;

    for package in packages {
        let name = package
            .Id()
            .and_then(|id| id.Name())
            .map_err(|e| format!("read a registered Windows package identity: {e}"))?;
        if name
            .to_string_lossy()
            .eq_ignore_ascii_case(CLAUDE_PACKAGE_NAME)
        {
            return Ok(true);
        }
    }
    Ok(false)
}
