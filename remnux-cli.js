const cfg = require('./config.json')
const os = require('os')
const fs = require('fs').promises
const fsSync = require('fs')
const child_process = require('child_process')
const { promisify } = require('util')
const crypto = require('crypto')
const spawn = require('child_process').spawn
const docopt = require('docopt').docopt
const { Octokit } = require('@octokit/rest')
const openpgp = require('openpgp')
const username = require('username')
const readline = require('readline')
const split = require('split')
const execAsync = promisify(child_process.exec)
const yaml = require('js-yaml')

const currentUser = process.env.SUDO_USER || username.sync()

const doc = `
Usage:
  remnux [options] list-upgrades [--pre-release]
  remnux [options] install [--pre-release] [--version=<version>] [--mode=<mode>] [--user=<user>]
  remnux [options] upgrade [--pre-release] [--mode=<mode>] [--user=<user>]
  remnux [options] results [--version=<version>]
  remnux [options] version
  remnux [options] debug
  remnux -h | --help | -v

Options:
  --dev                 Developer Mode (do not use, dangerous, bypasses checks)
  --version=<version>   Specific version to install or check results for [default: latest]
  --mode=<mode>         REMnux installation mode (dedicated, addon, or cloud)
  --user=<user>         User used for REMnux configuration [default: ${currentUser}]
  --no-cache            Ignore the cache, always download the release files
  --verbose             Display verbose logging
`

const validModes = ['dedicated', 'addon','cloud']
const supported = ['focal', 'noble'];
const saltstackVersion = '3006'
let remnuxVersion = null
const pubKey = `
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
fSjkH+LA6A==
=16sr
-----END PGP PUBLIC KEY BLOCK-----
`

const getHelpText = () => {
let logFilePath
let subDir
if (remnuxVersion != null) {
    logFilePath = `${cfg.logPath}/${remnuxVersion}`
    subDir = '.'
}
else {
    logFilePath = cfg.logPath
    subDir = " in the subdirectory that matches the REMnux release version you're installing."
}
  return `
Try rebooting your system and trying the operation again.

Sometimes problems occur due to network or server issues when
downloading packages, in which case retrying your operation
a bit later might lead to a better result.
Additionally, if you are operating behind a proxy, you may
need to configure your environment to allow access through
the proxy.

To determine the nature of the issue, please review the
saltstack.log file under ${logFilePath}${subDir}

Pay particular attention to lines that start with [ERROR], or
which come before the line "result: false".

Otherwise, you can run:

sudo remnux results --version=<version>

Where <version> is the "upgrade-version:" value seen at the beginning of the install.

For assistance go to https://github.com/REMnux/remnux-cli/issues
`
};

let cachePath = '/var/cache/remnux/cli'
let versionFile = '/etc/remnux-version'
let configFile = '/etc/remnux-config'
let releaseFile = '/etc/os-release'
let remnuxConfiguration = {}
let isModeSpecified = false

const cli = docopt(doc)

const github = new Octokit({
  version: '3.0.0',
  validateCache: true,
})

const error = (err) => {
  console.log('')
  console.log(err.message)
  console.log(err.stack)
  console.log(getHelpText())
  process.exit(1)
}

const setup = async () => {
  if (cli['--dev'] === true) {
    cachePath = '/tmp/var/cache/remnux'
    versionFile = '/tmp/remnux-version'
    configFile = '/tmp/remnux-config'
    releaseFile = '/tmp/os-release'
  }

  await fs.mkdir(cachePath, { recursive: true })
}

const validOS = async () => {
  try {
    const contents = await fs.readFile(releaseFile, 'utf8')
    const match = contents.match(/UBUNTU_CODENAME=["']?(\w+)["']?/);
    if (!match) {
      throw new Error('Invalid OS or unable to determine Ubuntu version')
    }
    const codename = match[1];
    if (supported.includes(codename)) {
      return true;
    }
    throw new Error(`Unsupported Ubuntu version: ${codename}`);
  } catch (err) {
    if (err?.code === 'ENOENT') {
      throw new Error('Invalid OS, missing ${releaseFile}')
    }
    throw err;
  }
}

const checkOptions = () => {
  if (cli['--mode'] != null) {
    if (validModes.indexOf(cli['--mode']) === -1) {
      throw new Error(`${cli['--mode']} is not a valid install mode. Valid modes are: ${validModes.join(', ')}`)
    }
    else {
      isModeSpecified = true
    }
  }
}

const fileExists = async (path) => {
  try {
    await fs.stat(path)
    return true
  } catch (err) {
    if (err.code === 'ENOENT') {
      return false
    }
    throw err
  }
}

const saltCheckVersion = async (path, value) => {
  try {
    const contents = await fs.readFile(path, 'utf8')
    return contents.indexOf(value) === 0
  } catch (err) {
    if (err.code === 'ENOENT') {
      return false
    }
    throw err
  }
}

const setupSalt = async () => {
  if (cli['--dev'] === false) {
    const baseUrl = 'https://packages.broadcom.com'
    
    // Support both remnux-cli and Cast apt source file locations
    const aptSourceListLegacy = '/etc/apt/sources.list.d/saltstack.list'
    const aptSourceListCast = '/etc/apt/sources.list.d/salt.list'
    
    // Accept either key path as valid (remnux-cli uses /usr/share/keyrings, Cast uses /etc/apt/keyrings)
    const keyPathLegacy = '/usr/share/keyrings/salt-archive-keyring.pgp'
    const keyPathCast = '/etc/apt/keyrings/salt-archive-keyring-2023.pgp'
    
    const aptDebStringLegacy = `deb [signed-by=${keyPathLegacy} arch=amd64] ${baseUrl}/artifactory/saltproject-deb/ stable main`
    const aptDebStringCast = `deb [signed-by=${keyPathCast} arch=amd64] ${baseUrl}/artifactory/saltproject-deb/ stable main`

    const aptExistsLegacy = await fileExists(aptSourceListLegacy)
    const aptExistsCast = await fileExists(aptSourceListCast)
    const aptExists = aptExistsLegacy || aptExistsCast
    
    const saltExists = await fileExists('/usr/bin/salt-call')
    
    // Check if either configuration is valid
    const saltVersionOkLegacy = await saltCheckVersion(aptSourceListLegacy, aptDebStringLegacy)
    const saltVersionOkCast = await saltCheckVersion(aptSourceListCast, aptDebStringCast)
    const saltVersionOk = saltVersionOkLegacy || saltVersionOkCast

    if (aptExists === true && saltVersionOk === false) {
      console.log('NOTICE: Fixing incorrect Saltstack version configuration.')
      console.log('Installing and configuring Saltstack properly ...')
      await execAsync('apt-get remove -y --allow-change-held-packages salt-common salt-minion')
      await execAsync('mkdir -p /usr/share/keyrings')
      await execAsync(`curl -fsSL -o ${keyPathLegacy} ${baseUrl}/artifactory/api/security/keypair/SaltProjectKey/public`)
      await fs.writeFile(aptSourceListLegacy, aptDebStringLegacy)
      await execAsync(`printf 'Package: salt-*\nPin: version ${saltstackVersion}.*\nPin-Priority: 1001' > /etc/apt/preferences.d/salt-pin-1001`)
      await execAsync('apt-get update')
      await execAsync('apt-get install -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y --allow-change-held-packages salt-common', {
        env: {
          ...process.env,
          DEBIAN_FRONTEND: 'noninteractive',
        },
      })
    } else if (aptExists === false || saltExists === false) {
      console.log('Installing and configuring SaltStack...')
      await fs.writeFile(aptSourceListLegacy, aptDebStringLegacy)
      await execAsync('mkdir -p /usr/share/keyrings')
      await execAsync(`curl -fsSL -o ${keyPathLegacy} ${baseUrl}/artifactory/api/security/keypair/SaltProjectKey/public`)
      await execAsync(`printf 'Package: salt-*\nPin: version ${saltstackVersion}.*\nPin-Priority: 1001' > /etc/apt/preferences.d/salt-pin-1001`)
      await execAsync('apt-get update')
      await execAsync('apt-get install -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y --allow-change-held-packages salt-common', {
        env: {
          ...process.env,
          DEBIAN_FRONTEND: 'noninteractive',
        },
      })
    }
  } else {
    return Promise.resolve();
  }
}

const getCurrentVersion = async () => {
  try {
    const contents = await fs.readFile(versionFile)
    return contents.toString().replace(/\n/g, '')
  } catch (err) {
    if (err.code === 'ENOENT') {
      return 'not installed'
    }
    throw err
  }
}

const listReleases = () => {
  return github.repos.listReleases({
    owner: 'REMnux',
    repo: 'salt-states'
  })
}

const getValidReleases = async () => {
  const currentRelease = await getCurrentVersion()
  let releases = await listReleases()
  const realReleases = releases.data.filter(release => !release.prerelease).map(release => release.tag_name)
  const allReleases = releases.data.map(release => release.tag_name)

  if (currentRelease === 'not installed') {
    if (cli['--pre-release'] === true) {
      return allReleases
    }
    return realReleases
  }

  let curIndex = allReleases.indexOf(currentRelease)
  if (curIndex === 0) {
    return [allReleases[0]]
  }

  if (cli['--pre-release'] === true) {
    return allReleases.slice(0, curIndex)
  }

  return allReleases.slice(0, curIndex).filter((release) => {
    return realReleases.indexOf(release) !== -1
  })
}

const getLatestRelease = async () => {
  const releases = await getValidReleases()
  return releases[0]
}

const isValidRelease = async (version) => {
  const releases = await getValidReleases()
  return releases.indexOf(version) !== -1
}

const validateVersion = async (version) => {
  const releases = await getValidReleases()
  if (releases.indexOf(version) === -1) {
    throw new Error('The version you are attempting to install/upgrade to is not valid.')
  }
}

const downloadReleaseFile = async (version, filename) => {
  console.log(`> downloading ${filename}`)

  const filepath = `${cachePath}/${version}/${filename}`
  const url = `https://github.com/REMnux/salt-states/releases/download/${version}/${filename}`
  if (fsSync.existsSync(filepath) && cli['--no-cache'] === false) {
    return Promise.resolve()
  }
  const response = await fetch(url)
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`)
  }
  const output = fsSync.createWriteStream(filepath)
  return new Promise((resolve, reject) => {
    const reader = response.body.getReader()
    const pump = async () => {
      try {
        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          output.write(value)
        }
        output.end()
      } catch (err) {
        output.destroy()
        await fs.unlink(filepath).catch(() => {})
        reject(err)
      }
    }
    output.on('error', (err) => {
      output.destroy()
      fs.unlink(filepath, () => {})
      reject(err)
    })
    output.on('finish', () => {
      resolve()
    })
    pump()
  })
}

const downloadRelease = async (version) => {
  console.log(`> downloading remnux-salt-states-${version}.tar.gz`)
  const filepath = `${cachePath}/${version}/remnux-salt-states-${version}.tar.gz`
  if (fsSync.existsSync(filepath) && cli['--no-cache'] === false) {
    return Promise.resolve()
  }
  const response = await fetch(`https://github.com/REMnux/salt-states/archive/${version}.tar.gz`)
  if (!response.ok) {
    throw new Error(`fetch error - status: ${response.status}`)
  }
  const output = fsSync.createWriteStream(filepath)
  const reader = response.body.getReader()
  return new Promise((resolve, reject) => {
    const pump = async () => {
      try {
        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          output.write(value)
        }
        output.end()
        resolve()
      } catch (err) {
        output.destroy()
        await fs.unlink(filepath).catch(() => {})
        reject(err)
      }
    }

    output.on('error', (err) => {
      output.destroy()
      fs.unlink(filepath, () => {})
      reject(err)
    })
    pump()
  })
}

const validateFile = async (version, filename) => {
  console.log(`> validating file ${filename}`)
  const expected = await fs.readFile(`${cachePath}/${version}/${filename}.sha256`)
  const actual = await new Promise((resolve, reject) => {
    const shasum = crypto.createHash('sha256')
    fsSync.createReadStream(`${cachePath}/${version}/${filename}`)
      .on('error', (err) => {
        reject(err)
      })
      .on('data', (data) => {
        shasum.update(data)
      })
      .on('close', () => {
        resolve(`${shasum.digest('hex')}  /tmp/${filename}\n`)
      })
  })
  if (expected.toString() !== actual) {
    throw new Error(`Hashes for ${filename} do not match. Expected: ${expected}. Actual: ${actual}.`)
  }
}

const validateSignature = async (version, filename) => {
  console.log(`> validating signature for ${filename}`)

  const filepath = `${cachePath}/${version}/${filename}`
  const ctSignature = await fs.readFile(`${filepath}.asc`, 'utf8')
  const ctPubKey = pubKey
  const publicKey = await openpgp.readKey({ armoredKey: ctPubKey })
  const cleartextMessage = await openpgp.readCleartextMessage({ cleartextMessage: ctSignature })
  const valid = await openpgp.verify({
    message: cleartextMessage,
    verificationKeys: publicKey
  });

  if (!valid.signatures || valid.signatures.length === 0) {
    throw new Error('Invalid Signature')
  }

  const isValid = await valid.signatures[0].verified
  if (!isValid) {
    throw new Error('PGP Signature is not valid')
  }
}

const extractUpgrade = (version, filename) => {
  const filepath = `${cachePath}/${version}/${filename}`

  return new Promise((resolve, reject) => {
    console.log(`> extracting upgrade ${filename}`)

    let stdout = ''
    let stderr = ''
    const extract = spawn('tar', ['-z', '-x', '-f', filepath, '-C', `${cachePath}/${version}`])
    extract.stdout.on('data', (data) => {
      stdout = `${stdout}${data}`
      console.log(data.toString())
    })
    extract.stderr.on('data', (data) => {
      stderr = `${stderr}${data}`
      console.log(data.toString())
    })
    extract.on('error', (err) => {
      reject(err)
    })
    extract.on('close', (code) => {
      if (code !== 0) {
        return reject(new Error('Extraction returned exit code not zero'))
      }

      resolve()
    })
  })
}

const downloadUpgrade = async (version) => {
  console.log(`> upgrade-version: ${version}`)
  await fs.mkdir(`${cachePath}/${version}`, { recursive: true })
  await downloadReleaseFile(version, `remnux-salt-states-${version}.tar.gz.asc`)
  await downloadReleaseFile(version, `remnux-salt-states-${version}.tar.gz.sha256`)
  await downloadReleaseFile(version, `remnux-salt-states-${version}.tar.gz.sha256.asc`)
  await downloadRelease(version)
  await validateFile(version, `remnux-salt-states-${version}.tar.gz`)
  await validateSignature(version, `remnux-salt-states-${version}.tar.gz.sha256`)
  await extractUpgrade(version, `remnux-salt-states-${version}.tar.gz`)
}

const performUpgrade = (version) => {
  const filepath = `${cachePath}/${version}/salt-states-${version.replace('v', '')}`
  const outputFilepath = `${cachePath}/${version}/results.yml`
  const logFilepath = `${cachePath}/${version}/saltstack.log`
  cfg.logPath = logFilepath
  const begRegex = /Running state \[(.*)\] at time (.*)/g
  const endRegex = /Completed state \[(.*)\] at time (.*) duration_in_ms=(.*)/g

  const stateApplyMap = {
    'dedicated': 'remnux.dedicated',
    'addon': 'remnux.addon',
    'cloud': 'remnux.cloud'
  }
 
  if (!isModeSpecified) {
    let savedMode = remnuxConfiguration['mode']
    if (validModes.indexOf(savedMode) != -1) {
      cli['--mode'] = savedMode
	    console.log(`> using previous mode: ${cli['--mode']}`)
    }  else {
      console.log(`> no previous REMnux version found; performing a new 'dedicated' installation.`)
      cli['--mode'] = "dedicated"
    }
  }

  return new Promise((resolve, reject) => {
    console.log(`> upgrading/updating to ${version}`)
    console.log(`>> Log file: ${logFilepath}`)

    if (os.platform() !== 'linux') {
      console.log(`>>> Platform is not Linux`)
      return process.exit(1)
    }

    let stderr = ''

    const logFile = fsSync.createWriteStream(logFilepath)

    const upgradeArgs = [
      '-l', 'debug', '--local',
      '--file-root', filepath,
      '--state-output=terse',
      '--out=yaml',
      'state.apply', stateApplyMap[cli['--mode']],
      `pillar={remnux_user: "${remnuxConfiguration['user']}"}`
    ]

    const upgrade = spawn('salt-call', upgradeArgs)

    upgrade.stdout.pipe(fsSync.createWriteStream(outputFilepath))
    upgrade.stdout.pipe(logFile)
    upgrade.stderr.pipe(logFile)
    upgrade.stderr
      .pipe(split())
      .on('data', (data) => {
        stderr = `${stderr}${data}`

        const begMatch = begRegex.exec(data)
        const endMatch = endRegex.exec(data)

        if (begMatch !== null) {
          process.stdout.write(`\n> Running: ${begMatch[1]}\r`)
        } else if (endMatch !== null) {
          let message = `> Completed: ${endMatch[1]} (Took: ${endMatch[3]} ms)`
          if (process.stdout.isTTY === true) {
            readline.clearLine(process.stdout, 0)
            readline.cursorTo(process.stdout, 0)
          }
          process.stdout.write(`${message}`)
        }
      })
    upgrade.on('error', (err) => {
      console.log(arguments)
      reject(err)
    })
    upgrade.on('close', (code) => {
      if (code !== 0) {
        return summarizeResults(version)
          .then(() => {
            reject(new Error(`Upgrade returned non-zero exit code (${code})`));
          })
          .catch((err) => {
            console.log('Failed to summarize results:', err);
            reject(new Error(`Upgrade returned non-zero exit code (${code}) and summary failed`));
          });
      }
      process.nextTick(resolve)
    })
  })
}

const summarizeResults = async (version) => {
  const outputFilepath = `${cachePath}/${version}/results.yml`
  if (await fileExists(outputFilepath)) {
    const rawContents = await fs.readFile(outputFilepath, 'utf8')
    let results = {}

    results = yaml.load(rawContents)

    let success = 0
    let failure = 0
    let failures = [];
    Object.keys(results['local']).forEach((key) => {
      if (results['local'][key]['result'] === true) {
        success++
      } else {
        failure++
        failures.push(results['local'][key])
      }
    })

    if (failure > 0) {
      console.log(`\n> Incomplete due to Failures -- Success: ${success}, Failure: ${failure}`)
      console.log(`\r>>>> List of Failures (first 10 only)`)
      console.log(`\r     NOTE: First failure is generally the root cause.`)
      console.log(`\n     IMPORTANT: If seeking assistance, include this information,`)
      console.log(`\r     AND the /var/cache/remnux/cli/${version}/saltstack.log.\n`)
      failures.sort((a, b) => {
      return a['__run_num__'] - b['__run_num__']
      }).slice(0, 10).forEach((key) => {
        console.log(`      - ID: ${key['__id__']}`)
        console.log(`        SLS: ${key['__sls__']}`)
        console.log(`        Run#: ${key['__run_num__']}`)
        console.log(`        Comment: ${key['comment']}`)
      })
      console.log(`\r`)
      return Promise.resolve()
    }

    console.log(`\n>> COMPLETED SUCCESSFULLY! Success: ${success}, Failure: ${failure}`)
    console.log(`\n>> Please reboot to make sure all settings take effect.`)
  } else {
    console.log(`The file ${outputFilepath} does not exist!\nIf using the "results" option make sure you specify the version with --version.`)
    process.exit(1)
  }
}

const saveConfiguration = (version) => {
  const config = {
    version: version,
    mode: cli['--mode'],
    user: cli['--user']
  }

  return fs.writeFile(configFile, yaml.dump(config))
}

const loadConfiguration = async () => {
  try {
    const contents = await fs.readFile(configFile, 'utf8')
    return yaml.load(contents)
  } catch (err) {
    if (err.code === 'ENOENT') {
      return {
        mode: 'unknown',
        user: cli['--user']
      }
    }
    throw err
  }
}

const run = async () => {
  if (cli['-v'] === true) {
    console.log(`Version: ${cfg.version}`)
    return process.exit(0)
  }

  console.log(`> remnux-cli@${cfg.version}`)

  if (cli['debug'] === true) {
    const config = await loadConfiguration()

    const debug = `
Version: ${cfg.version}
User: ${currentUser}
Log Path: ${cfg.logPath}
Config:
${yaml.dump(config)}
`
    console.log(debug)
    return process.exit(0)
  }

  if (currentUser === 'root') {
    console.log('Warning: You are running as root.')
    if (currentUser === cli['--user']) {
      console.log('Error: You cannot install as root without specifying the --user option.')
      console.log()
      console.log('The install user specified with --user must not be the root user.')
      return process.exit(5)
    }
  }

  checkOptions()

  await validOS()

  await setup()

  remnuxConfiguration = await loadConfiguration()

  const version = await getCurrentVersion()
  console.log(`> remnux-version: ${version}\r`)

  if (isModeSpecified) {
    console.log(`> Mode: ${cli['--mode']}`)
  }

  if (cli['version'] === true) {
    return process.exit(0)
  }

  if (cli['list-upgrades'] === true) {
    const releases = await getValidReleases()
    const current = await getCurrentVersion()
    if (releases.length === 0 || releases[0] === current) {
      console.log('No upgrades available.')
      return process.exit(0)
    }

    console.log('> List of available releases')
    releases.forEach(release => console.log(`  - ${release}`))
    return process.exit(0)
  }

  if (!process.env.SUDO_USER && cli['--dev'] === false) {
    console.log('> Error! You must be root to execute this.')
    return process.exit(1)
  }

  if (cli['results'] === true && cli['--version'] !== null && cli['--version'] !== 'latest') {
    await summarizeResults(cli['--version'])
    return process.exit(0)
  }
  else if (cli['results'] === true && cli['--version'] === 'latest') {
    const currentVersion = await getCurrentVersion()
    if (currentVersion !== 'not installed') {
        await summarizeResults(currentVersion)
        return process.exit(0)
    } else {
      console.log('REMnux is not installed.')
      return process.exit(0)
    }
  }
  await setupSalt()
  if (cli['install'] === true) {
    const currentVersion = await getCurrentVersion()
    if (currentVersion !== 'not installed') {
      console.log('REMnux is already installed, please use the "upgrade" command.')
      return process.exit(0)
    }

    let versionToInstall = null
    if (cli['--version'] === 'latest') {
      versionToInstall = await getLatestRelease()
      remnuxVersion = versionToInstall
    } else {
      const validRelease = await isValidRelease(cli['--version'])

      if (validRelease === false) {
        console.log(`${cli['--version']} is not a REMnux valid release.`)
        return process.exit(5)
      }

      versionToInstall = cli['--version']
      remnuxVersion = versionToInstall
    }

    if (versionToInstall === null) {
      throw new Error('versionToInstall was null, this should never happen.')
    }

    await validateVersion(versionToInstall)
    await downloadUpgrade(versionToInstall)
    await performUpgrade(versionToInstall)
    await summarizeResults(versionToInstall)
    await saveConfiguration(versionToInstall)
  }

  if (cli['upgrade'] === true) {
    const release = await getLatestRelease()
    const current = await getCurrentVersion()

    if (release === current || typeof release === 'undefined') {
      console.log('No upgrades available')
      process.exit(0)
    }

    remnuxVersion = release
    await downloadUpgrade(release)
    await performUpgrade(release)
    await summarizeResults(release)
  }
}

const main = async () => {
  try {
    await run()
  } catch (err) {
    error(err)
  }
}

main()
