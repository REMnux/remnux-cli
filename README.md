# REMnux Distro CLI

Manage Your REMnux Distro Installation

*This tool is still a work in progress. Don't expect it to work yet.*

## Usage

```
Usage:
  remnux [options] list-upgrades [--pre-release]
  remnux [options] install [--pre-release] [--version=<version>] [--mode=<mode>] [--user=<user>]
  remnux [options] update [--mode=<mode>]
  remnux [options] upgrade [--pre-release] [--mode=<mode>]
  remnux [options] self-upgrade [--pre-release]
  remnux [options] version
  remnux [options] debug
  remnux -h | --help | -v

Options:
  --dev                 Developer Mode (do not use, dangerous, bypasses checks)
  --version=<version>   Specific version install [default: latest]
  --mode=<mode>         REMnux Install Mode (dedicated or addon) [default: addon]
  --user=<user>         User used for REMnux configuration [default: ${currentUser}]
  --no-cache            Ignore the cache, always download the release files
  --verbose             Display verbose logging
```

## Issues

Open issues over at the [REMnux distro repository](https://github.com/REMnux/distro/issues).

## Installation

1. Go to the [Latest Releases](https://github.com/REMnux/remnux-cli/releases/latest)
2. Download all the release files
    * remnux-cli-linux
    * remnux-cli-linux.sha256.asc
3. Import the PGP Key - `gpg --keyserver hkp://pool.sks-keyservers.net:80 --recv-keys 28CD19DB`
4. Validate the signature `gpg --verify remnux-cli-linux.sha256.asc`
5. Validate SHA256 signature `shasum -a 256 -c remnux-cli-linux.sha256.asc` OR `sha256sum -c remnux-cli-linux.sha256.asc`
    * Note: You'll see an error about improperly formatted lines, it
      can be ignored so long as you see `remnux-cli-linux: OK` before it
6. Move the file to `sudo mv remnux-cli-linux /usr/local/bin/remnux`
7. Run `chmod 755 /usr/local/bin/remnux`
8. Type `remnux --help` to see its usage

## Examples

### Install the Latest REMnux Distro on a Dedicated System

```bash
remnux install --mode=dedicated
```

### Install Latest REMnux Distro in Addon Mode

Addon mode only installs tools and packages, it does not do any modifications that would normally appear on the desktop.

```bash
remnux install --mode=addon
```

### Install Specific Version

```bash
remnux install v2019.11.0
```

### Update Existing VM

This just makes sure the current version is up-to-date

```bash
remnux update
```

### Upgrading to a New REMnux Release

```bash
remnux upgrade
```
