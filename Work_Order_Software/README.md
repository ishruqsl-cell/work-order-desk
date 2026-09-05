# Work Order Desk — Simple Local Software

This version does **not** require a User ID or Password.

## Install / Start

1. Extract the ZIP to a permanent folder, e.g. `C:\Work Order Desk`.
2. Double-click **START_WORK_ORDER.bat**.
3. On the first run, it installs the required components automatically. If Node.js is missing, it attempts to install Node.js LTS with Windows `winget`.
4. Your browser opens the software automatically at `http://localhost:3000`.

## Data safety

- Work Orders are stored in `data/workorders.db` (SQLite), not browser storage.
- Editing a Work Order creates a new permanent version in the database.
- Work Orders are archived rather than physically deleted.
- Use `BACKUP_DATA.bat` regularly to make a database backup in the `backups` folder.
- Keep the entire software folder in a permanent location and do not delete `data`.

## Excel

The Download Excel function creates a formatted `.xlsx` file with borders, bold headers, totals, Terms & Conditions, and a fixed two-column signature layout.

## Stop / Start

- Stop: close the black server window.
- Start again: double-click **START_WORK_ORDER.bat**.
