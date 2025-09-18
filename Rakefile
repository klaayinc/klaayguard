require "open-uri"

def log(msg)
    puts "osquery bundle: #{msg}"
end

DIR_TMP = "tmp"
DIR_SIDECAR = "src-tauri/vendor"

file DIR_TMP do
    log "Creating temp dir..."
    Dir.mkdir(DIR_TMP) unless Dir.exist?(DIR_TMP)
end

OSQUERY_VERSION = "5.18.1"

# macOS binary (used to produce both darwin suffix variants)
TARBALL_FILE = "osqueryd-macos-bare-#{OSQUERY_VERSION}.tar.gz"
TARBALL_PATH = File.join(DIR_TMP, TARBALL_FILE)

# Linux binary (x86_64 GNU)
LINUX_TARBALL_FILE = "osqueryd-linux-bare-#{OSQUERY_VERSION}.tar.gz"
LINUX_TARBALL_PATH = File.join(DIR_TMP, LINUX_TARBALL_FILE)

file TARBALL_PATH => [DIR_TMP] do
    log "Downloading tarball.."
    response = URI.open("https://github.com/osquery/osquery/releases/download/#{OSQUERY_VERSION}/#{TARBALL_FILE}")
    File.write(TARBALL_PATH, response.read)
end 

file LINUX_TARBALL_PATH => [DIR_TMP] do
    log "Downloading linux tarball.."
    response = URI.open("https://github.com/osquery/osquery/releases/download/#{OSQUERY_VERSION}/#{LINUX_TARBALL_FILE}")
    File.write(LINUX_TARBALL_PATH, response.read)
end

OSQUERYD_PATH = File.join(DIR_TMP, "osqueryd")
OSQUERYD_LINUX_PATH = File.join(DIR_TMP, "osqueryd-linux")

file OSQUERYD_PATH => [TARBALL_PATH] do
    log "Extracting tarball.."
    sh "tar -xvzf #{TARBALL_PATH} -C #{DIR_TMP}"
    sh "chmod +x #{OSQUERYD_PATH}"
end

file OSQUERYD_LINUX_PATH => [LINUX_TARBALL_PATH] do
    log "Extracting linux tarball.."
    # Extract into a separate filename to avoid clobbering macOS binary when running both
    sh "tar -xvzf #{LINUX_TARBALL_PATH} -C #{DIR_TMP}"
    # The extracted binary is named osqueryd; duplicate to dedicated filename for task dependency clarity
    sh "cp #{File.join(DIR_TMP, 'osqueryd')} #{OSQUERYD_LINUX_PATH}"
    sh "chmod +x #{OSQUERYD_LINUX_PATH}"
end

OSQUERYI_PATH = File.join(DIR_SIDECAR, "osqueryi")

file OSQUERYI_PATH => [OSQUERYD_PATH] do
    sh "mkdir -p #{DIR_SIDECAR}"
    sh "cp #{OSQUERYD_PATH} #{OSQUERYI_PATH}-aarch64-apple-darwin"
    sh "cp #{OSQUERYD_PATH} #{OSQUERYI_PATH}-x86_64-apple-darwin"
end

OSQUERYI_LINUX_X64_PATH = File.join(DIR_SIDECAR, "osqueryi-x86_64-unknown-linux-gnu")

file OSQUERYI_LINUX_X64_PATH => [OSQUERYD_LINUX_PATH] do
    sh "mkdir -p #{DIR_SIDECAR}"
    sh "cp #{OSQUERYD_LINUX_PATH} #{OSQUERYI_LINUX_X64_PATH}"
end

task :clean do
    sh "rm -rf tmp"
    sh "rm -f src-tauri/vendor/osqueryi*"
end

task default: [OSQUERYI_PATH, OSQUERYI_LINUX_X64_PATH]


