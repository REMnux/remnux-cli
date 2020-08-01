# REMnux Installer

This repository contains the source code for the REMnux installer, which is the command-line tool for installing and upgrading the [REMnux](https://REMnux.org) distro.

If troubleshooting an issue related to an unsuccessful run of the REMnux installer, review the saltstack.log file under /var/cache/remnux/cli in the
subdirectory that matches the REMnux version you're installing. Search for the log file for `result: false` and look at the surrounding 5 lines on either side, or the 8 lines above it to see the SaltStack state file that caused the issue. (`grep -i -C 5 'result: false'` or `grep -i -B 8 'result: false'`).
