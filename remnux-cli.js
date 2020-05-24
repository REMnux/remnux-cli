const cfg = require('./config.json')
const bluebird = require('bluebird')
const os = require('os')
const fs = bluebird.promisifyAll(require('fs'))
const child_process = bluebird.promisifyAll(require('child_process'))
const crypto = require('crypto')
const spawn = require('child_process').spawn
const docopt = require('docopt').docopt
const GitHubApi = require('github')
const mkdirp = bluebird.promisify(require('mkdirp'))
const request = require('request')
const openpgp = require('openpgp')
const username = require('username')
const readline = require('readline')
const split = require('split')
const semver = require('semver')

/**
 * Setup Custom YAML Parsing
 */
const yaml = require('js-yaml')
const PythonUnicodeType = new yaml.Type('tag:yaml.org,2002:python/unicode', {
  kind: 'scalar',
  construct: (data) => { return data !== null ? data : ''; }
})
const PYTHON_SCHEMA = new yaml.Schema({
  include: [yaml.DEFAULT_SAFE_SCHEMA],
  explicit: [PythonUnicodeType]
})

const currentUser = process.env.SUDO_USER || username.sync()

const doc = `
Usage:
  remnux [options] list-upgrades [--pre-release]
  remnux [options] install [--pre-release] [--version=<version>] [--mode=<mode>] [--user=<user>]
  remnux [options] update
  remnux [options] upgrade [--pre-release] [--mode=<mode>] [--user=<user>]
  remnux [options] version
  remnux [options] debug
  remnux -h | --help | -v

Options:
  --dev                 Developer Mode (do not use, dangerous, bypasses checks)
  --version=<version>   Specific version install [default: latest]
  --mode=<mode>         REMnux installation mode (dedicated or addon) [default: addon]
  --user=<user>         User used for REMnux configuration [default: ${currentUser}]
  --no-cache            Ignore the cache, always download the release files
  --verbose             Display verbose logging
`

const saltstackVersion = '2019.2'
const pubKey = `
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG

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
fSjkH+LA6A==
=16sr
-----END PGP PUBLIC KEY BLOCK-----
`

const help = `

To determine the nature of the issue, please review the
saltstack.log file under /var/cache/remnux/cli in the
subdirectory that matches the REMnux version you're installing.
Pay particular attention to lines that start with [ERROR].

Sometimes problems occur due to network or server issues when
downloading packages, in which case retrying your operation
a bit later might lead to good results.
`

let osVersion = null
let osCodename = null
let cachePath = '/var/cache/remnux/cli'
let versionFile = '/etc/remnux-version'
let configFile = '/etc/remnux-config'
let remnuxConfiguration = {}

const cli = docopt(doc)

const github = new GitHubApi({
  version: '3.0.0',
  validateCache: true,
})

const error = (err) => {
  console.log('')
  console.log(err.message)
  console.log(err.stack)
  console.log(help)
  process.exit(1)
}

const setup = async () => {
  if (cli['--dev'] === true) {
    cachePath = '/tmp/var/cache/remnux'
    versionFile = '/tmp/remnux-version'
    configFile = '/tmp/remnux-config'
  }

  await mkdirp(cachePath)
}

const validOS = async () => {
  try {
    const contents = fs.readFileSync('/etc/os-release', 'utf8')

    if (contents.indexOf('UBUNTU_CODENAME=bionic') !== -1) {
      osVersion = '18.04'
      osCodename = 'bionic'
      return true
    }

    throw new Error('Invalid OS or unable to determine Ubuntu version')
  } catch (err) {
    if (err && err.code === 'ENOENT') {
      throw new Error('invalid OS, missing /etc/os-release')
    }

    throw err
  }
}

const checkOptions = () => {
  const validModes = ['dedicated', 'addon']

  if (validModes.indexOf(cli['--mode']) === -1) {
    throw new Error(`${cli['--mode']} is not a valid install mode. Valid modes are: ${validModes.join(', ')}`)
  }
}

const fileExists = (path) => {
  return new Promise((resolve, reject) => {
    fs.stat(path, (err, stats) => {
      if (err && err.code === 'ENOENT') {
        return resolve(false)
      }

      if (err) {
        return reject(err)
      }

      return resolve(true)
    })
  })
}

const saltCheckVersion = (path, value) => {
  return new Promise((resolve, reject) => {
    fs.readFile(path, 'utf8', (err, contents) => {
      if (err && err.code === 'ENOENT') {
        return resolve(false);
      }

      if (err) {
        return reject(err);
      }

      if (contents.indexOf(value) === 0) {
        return resolve(true);
      }

      return resolve(false);
    })
  })
}

const setupSalt = async () => {
  if (cli['--dev'] === false) {
    const aptSourceList = '/etc/apt/sources.list.d/saltstack.list'
    const aptDebString = `deb http://repo.saltstack.com/apt/ubuntu/${osVersion}/amd64/${saltstackVersion} ${osCodename} main`

    const aptExists = await fileExists(aptSourceList)
    const saltExists = await fileExists('/usr/bin/salt-call')
    const saltVersionOk = await saltCheckVersion(aptSourceList, aptDebString)

    if (aptExists === true && saltVersionOk === false) {
      console.log('NOTICE: Fixing incorrect Saltstack version configuration.')
      console.log('Installing and configuring Saltstack properly ...')
      await child_process.execAsync('apt-get remove -y --allow-change-held-packages salt-minion salt-common')
      await fs.writeFileAsync(aptSourceList, `deb http://repo.saltstack.com/apt/ubuntu/${osVersion}/amd64/${saltstackVersion} ${osCodename} main`)
      await child_process.execAsync(`wget -O - https://repo.saltstack.com/apt/ubuntu/${osVersion}/amd64/${saltstackVersion}/SALTSTACK-GPG-KEY.pub | apt-key add -`)
      await child_process.execAsync('apt-get update')
      await child_process.execAsync('apt-get install -y --allow-change-held-packages salt-minion')
    } else if (aptExists === false || saltExists === false) {
      console.log('Installing and configuring SaltStack properly ...')
      await fs.writeFileAsync(aptSourceList, `deb http://repo.saltstack.com/apt/ubuntu/${osVersion}/amd64/${saltstackVersion} ${osCodename} main`)
      await child_process.execAsync(`wget -O - https://repo.saltstack.com/apt/ubuntu/${osVersion}/amd64/${saltstackVersion}/SALTSTACK-GPG-KEY.pub | apt-key add -`)
      await child_process.execAsync('apt-get update')
      await child_process.execAsync('apt-get install -y --allow-change-held-packages salt-minion')
    }
  } else {
    return new Promise((resolve, reject) => {
      resolve()
    })
  }
}

const getCurrentVersion = () => {
  return fs.readFileAsync(versionFile)
    .catch((err) => {
      if (err.code === 'ENOENT') return 'notinstalled'
      if (err) throw err
    })
    .then(contents => contents.toString().replace(/\n/g, ''))
}

const getReleases = () => {
  return github.repos.getReleases({
    owner: 'REMnux',
    repo: 'salt-states'
  })
}

const getValidReleases = async () => {
  const currentRelease = await getCurrentVersion()
  let releases = await getReleases()
  const realReleases = releases.data.filter(release => !Boolean(release.prerelease)).map(release => release.tag_name)
  const allReleases = releases.data.map(release => release.tag_name)

  if (currentRelease === 'notinstalled') {
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

const getLatestRelease = () => {
  return getValidReleases().then(releases => releases[0])
}

const isValidRelease = (version) => {
  return getValidReleases().then((releases) => {
    return new Promise((resolve, reject) => {
      if (releases.indexOf(version) === -1) {
        return resolve(false)
      }
      resolve(true)
    })
  })
}

const validateVersion = (version) => {
  return getValidReleases().then((releases) => {
    if (typeof releases.indexOf(version) === -1) {
      throw new Error('The version you are wanting to install/upgrade to is not valid.')
    }
    return new Promise((resolve) => { resolve() })
  })
}

const downloadReleaseFile = (version, filename) => {
  console.log(`>> downloading ${filename}`)

  const filepath = `${cachePath}/${version}/${filename}`

  if (fs.existsSync(filepath) && cli['--no-cache'] === false) {
    return new Promise((resolve) => { resolve() })
  }

  return new Promise((resolve, reject) => {
    const output = fs.createWriteStream(filepath)
    const req = request.get(`https://github.com/REMnux/salt-states/releases/download/${version}/${filename}`)
    req.on('error', (err) => {
      reject(err)
    })
    req
      .on('response', (res) => {
        if (res.statusCode !== 200) {
          throw new Error(res.body)
        }
      })
      .pipe(output)
      .on('error', (err) => {
        reject(err)
      })
      .on('close', resolve)
  })
}

const downloadRelease = (version) => {
  console.log(`>> downloading remnux-salt-states-${version}.tar.gz`)

  const filepath = `${cachePath}/${version}/remnux-salt-states-${version}.tar.gz`

  if (fs.existsSync(filepath) && cli['--no-cache'] === false) {
    return new Promise((resolve, reject) => { resolve() })
  }

  return new Promise((resolve, reject) => {
    const output = fs.createWriteStream(filepath)
    const req = request.get(`https://github.com/REMnux/salt-states/archive/${version}.tar.gz`)
    req.on('error', (err) => {
      reject(err)
    })
    req
      .pipe(output)
      .on('error', (err) => {
        reject(err)
      })
      .on('close', resolve)
  })
}

const validateFile = async (version, filename) => {
  console.log(`> validating file ${filename}`)
  const expected = await fs.readFileAsync(`${cachePath}/${version}/${filename}.sha256`)

  const actual = await new Promise((resolve, reject) => {
    const shasum = crypto.createHash('sha256')
    fs.createReadStream(`${cachePath}/${version}/${filename}`)
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

  const ctMessage = await fs.readFileAsync(`${filepath}`, 'utf8')
  const ctSignature = await fs.readFileAsync(`${filepath}.asc`, 'utf8')
  const ctPubKey = pubKey

  const options = {
    message: await openpgp.cleartext.readArmored(ctSignature),
    publicKeys: (await openpgp.key.readArmored(ctPubKey)).keys
  }

  const valid = await openpgp.verify(options)

  if (typeof valid.signatures === 'undefined' && typeof valid.signatures[0] === 'undefined') {
    throw new Error('Invalid Signature')
  }

  if (valid.signatures[0].valid === false) {
    throw new Error('PGP Signature is not valid')
  }
}

const extractUpdate = (version, filename) => {
  const filepath = `${cachePath}/${version}/${filename}`

  return new Promise((resolve, reject) => {
    console.log(`> extracting update ${filename}`)

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

const downloadUpdate = async (version) => {
  console.log(`> downloading ${version}`)

  await mkdirp(`${cachePath}/${version}`)
  await downloadReleaseFile(version, `remnux-salt-states-${version}.tar.gz.asc`)
  await downloadReleaseFile(version, `remnux-salt-states-${version}.tar.gz.sha256`)
  await downloadReleaseFile(version, `remnux-salt-states-${version}.tar.gz.sha256.asc`)
  await downloadRelease(version)
  await validateFile(version, `remnux-salt-states-${version}.tar.gz`)
  await validateSignature(version, `remnux-salt-states-${version}.tar.gz.sha256`)
  await extractUpdate(version, `remnux-salt-states-${version}.tar.gz`)
}

const performUpdate = (version) => {
  const filepath = `${cachePath}/${version}/salt-states-${version.replace('v', '')}`
  const outputFilepath = `${cachePath}/${version}/results.yml`
  const logFilepath = `${cachePath}/${version}/saltstack.log`

  const begRegex = /Running state \[(.*)\] at time (.*)/g
  const endRegex = /Completed state \[(.*)\] at time (.*) duration_in_ms=(.*)/g

  const stateApplyMap = {
    'addon': 'remnux.addon',
    'dedicated': 'remnux.dedicated'
  }

  return new Promise((resolve, reject) => {
    console.log(`> performing update ${version}`)

    console.log(`>> Log file: ${logFilepath}`)

    if (os.platform() !== 'linux') {
      console.log(`>>> Platform is not linux`)
      return process.exit(0)
    }

    let stdout = ''
    let stderr = ''

    const logFile = fs.createWriteStream(logFilepath)

    const updateArgs = [
      '-l', 'debug', '--local',
      '--file-root', filepath,
      '--state-output=terse',
      '--out=yaml',
      'state.apply', stateApplyMap[cli['--mode']],
      `pillar={remnux_user: "${remnuxConfiguration['user']}"}`
    ]

    const update = spawn('salt-call', updateArgs)

    update.stdout.pipe(fs.createWriteStream(outputFilepath))
    update.stdout.pipe(logFile)

    update.stderr.pipe(logFile)
    update.stderr
      .pipe(split())
      .on('data', (data) => {
        stderr = `${stderr}${data}`

        const begMatch = begRegex.exec(data)
        const endMatch = endRegex.exec(data)

        if (begMatch !== null) {
          process.stdout.write(`\n>> Running: ${begMatch[1]}\r`)
        } else if (endMatch !== null) {
          let message = `>> Completed: ${endMatch[1]} (Took: ${endMatch[3]} ms)`
          if (process.stdout.isTTY === true) {
            readline.clearLine(process.stdout, 0)
            readline.cursorTo(process.stdout, 0)
          }

          process.stdout.write(`${message}`)
        }
      })

    update.on('error', (err) => {
      console.log(arguments)

      reject(err)
    })
    update.on('close', (code) => {
      if (code !== 0) {
        return reject(new Error('Update returned exit code not zero'))
      }

      process.nextTick(resolve)
    })
  })
}

const summarizeResults = async (version) => {
  const outputFilepath = `${cachePath}/${version}/results.yml`
  const rawContents = await fs.readFileAsync(outputFilepath)
  let results = {}

  try {
    results = yaml.safeLoad(rawContents, { schema: PYTHON_SCHEMA })
  } catch (err) {
    // TODO handle?
  }

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
    console.log(`\n\n>> Incomplete due to Failures -- Success: ${success}, Failure: ${failure}`)
    console.log(`\n>>>> List of Failures (first 10 only)`)
    console.log(`\n     NOTE: First failure is generally the root cause.`)
    console.log(`\n     IMPORTANT: If seeking assistance, include this information.\n`)
    failures.sort((a, b) => {
      return a['__run_num__'] - b['__run_num__']
    }).slice(0, 10).forEach((key) => {
      console.log(`      - ID: ${key['__id__']}`)
      console.log(`        SLS: ${key['__sls__']}`)
      console.log(`        Run#: ${key['__run_num__']}`)
      console.log(`        Comment: ${key['comment']}`)
    })

    return new Promise((resolve, reject) => { return resolve() })
  }

  console.log(`\n\n>> COMPLETED SUCCESSFULLY! Success: ${success}, Failure: ${failure}`)
}

const saveConfiguration = (version) => {
  const config = {
    version: version,
    mode: cli['--mode'],
    user: cli['--user']
  }

  return fs.writeFileAsync(configFile, yaml.safeDump(config))
}

const loadConfiguration = async () => {
  try {
    return await fs.readFileAsync(configFile).then((c) => yaml.safeLoad(c))
  } catch (err) {
    if (err.code === 'ENOENT') {
      return {
        mode: cli['--mode'],
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

Config:
${yaml.safeDump(config)}
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
  console.log(`> remnux-version: ${version}\n`)

  console.log(`> mode: ${cli['--mode']}`)

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

  await setupSalt()

  if (cli['update'] === true) {
    if (version === 'notinstalled') {
      throw new Error('REMnux is not installed, unable to update.')
    }

    await downloadUpdate(version)
    await performUpdate(version)
    await summarizeResults(version)
  }

  if (cli['install'] === true) {
    const currentVersion = await getCurrentVersion(versionFile)

    if (currentVersion !== 'notinstalled') {
      console.log('REMnux is already installed, please use the update or upgrade command.')
      return process.exit(0)
    }

    let versionToInstall = null
    if (cli['--version'] === 'latest') {
      versionToInstall = await getLatestRelease()
    } else {
      const validRelease = await isValidRelease(cli['--version'])

      if (validRelease === false) {
        console.log(`${cli['--version']} is not a REMnux valid release.`)
        return process.exit(5)
      }

      versionToInstall = cli['--version']
    }

    if (versionToInstall === null) {
      throw new Error('versionToInstall was null, this should never happen.')
    }

    await validateVersion(versionToInstall)
    await downloadUpdate(versionToInstall)
    await performUpdate(versionToInstall)
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

    await downloadUpdate(release)
    await performUpdate(release)
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
