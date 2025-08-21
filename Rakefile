require "open-uri"

def log(msg)
    puts "osquery bundle: #{msg}"
end

# Create a temporary working directory
DIR_TMP = "tmp"
DIR_SIDECAR = "src-tauri/vendor"

file DIR_TMP do
    log "Creating temp dir..."
    Dir.mkdir(DIR_TMP) unless Dir.exist?(DIR_TMP)
end


# Download the MacOS tarball
OSQUERY_VERSION = "5.18.1"
TARBALL_FILE = "osqueryd-macos-bare-#{OSQUERY_VERSION}.tar.gz"
TARBALL_PATH = File.join(DIR_TMP, TARBALL_FILE)

file TARBALL_PATH => [DIR_TMP] do
    log "Downloading tarball.."
    response = URI.open("https://github.com/osquery/osquery/releases/download/#{OSQUERY_VERSION}/#{TARBALL_FILE}")
    File.write(TARBALL_PATH, response.read)
end 


# Extract the MacOS tarball
OSQUERYD_PATH = File.join(DIR_TMP, "osqueryd")

file OSQUERYD_PATH => [TARBALL_PATH] do
    log "Extracting tarball.."
    sh "tar -xvzf #{TARBALL_PATH} -C #{DIR_TMP}"
    sh "chmod +x #{OSQUERYD_PATH}"
end

# Rename to osqueryi. osqueryd and osqueryi are actually the same
# binary. it has different behaviour based on the name!
#
# Copy it to the sidecar directory at the same time

OSQUERYI_PATH = File.join(DIR_SIDECAR, "osqueryi")

file OSQUERYI_PATH => [OSQUERYD_PATH] do
    sh "cp #{OSQUERYD_PATH} #{OSQUERYI_PATH}-aarch64-apple-darwin"
    sh "cp #{OSQUERYD_PATH} #{OSQUERYI_PATH}-x86_64-apple-darwin"
end

task :clean do
    sh "rm -rf tmp"
    sh "rm -f src-tauri/vendor/osqueryi*"
end

task default: [OSQUERYI_PATH]