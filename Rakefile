require "open-uri"
require "json"
require "digest"

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
# Fetch and cache checksums from GitHub Releases for the pinned version
def fetch_release_assets
    url = "https://api.github.com/repos/osquery/osquery/releases/tags/#{OSQUERY_VERSION}"
    data = JSON.parse(URI.open(url).read)
    data["assets"] || []
end

def download_checksums_file
    assets = fetch_release_assets
    checksum_asset = assets.find { |a| a["name"] =~ /sha256/i }
    if checksum_asset
        path = File.join(DIR_TMP, checksum_asset["name"])
        File.write(path, URI.open(checksum_asset["browser_download_url"]).read)
        return path
    end

    # Fallback: Some releases embed per-asset SHA256 digests instead of publishing a checksum file.
    # Build a synthetic checksums file from the assets' digest fields.
    generated_path = File.join(DIR_TMP, "osquery-#{OSQUERY_VERSION}-SHA256SUMS.generated.txt")
    lines = assets
        .select { |a| a["digest"].to_s.start_with?("sha256:") && a["name"] }
        .map do |a|
            sha = a["digest"].sub(/^sha256:/, "").downcase
            filename = File.basename(a["name"])
            "#{sha}  #{filename}\n"
        end
    raise "No SHA256 digests available for osquery #{OSQUERY_VERSION}" if lines.empty?
    File.write(generated_path, lines.join)
    generated_path
end

def parse_checksums(path)
    map = {}
    File.read(path).each_line do |line|
        line = line.strip
        next if line.empty?
        # Format: <sha256>  <filename>
        if line =~ /^([0-9a-fA-F]{64})\s+\*?(.+)$/
            checksum = Regexp.last_match(1).downcase
            filename = File.basename(Regexp.last_match(2))
            map[filename] = checksum
            next
        end
        # Format: SHA256 (<filename>) = <sha256>
        if line =~ /^SHA256\s*\((.+)\)\s*=\s*([0-9a-fA-F]{64})$/
            filename = File.basename(Regexp.last_match(1))
            checksum = Regexp.last_match(2).downcase
            map[filename] = checksum
            next
        end
    end
    map
end

$osq_checksums = nil
def checksums
    $osq_checksums ||= parse_checksums(download_checksums_file)
end

def verify_checksum(file_path)
    filename = File.basename(file_path)
    expected = checksums[filename]
    raise "No checksum found for #{filename}" unless expected
    actual = Digest::SHA256.file(file_path).hexdigest
    raise "Checksum mismatch for #{filename}: expected #{expected}, got #{actual}" unless actual == expected
    log "Verified checksum for #{filename}"
end


# macOS binary (used to produce both darwin suffix variants)
TARBALL_FILE = "osqueryd-macos-bare-#{OSQUERY_VERSION}.tar.gz"
TARBALL_PATH = File.join(DIR_TMP, TARBALL_FILE)

# Linux binaries
# x86_64 GNU tarball (verified for 5.18.1)
LINUX_TARBALL_FILE = "osquery-#{OSQUERY_VERSION}_1.linux_x86_64.tar.gz"
LINUX_TARBALL_PATH = File.join(DIR_TMP, LINUX_TARBALL_FILE)
# aarch64 GNU tarball (present for recent osquery releases)
LINUX_AARCH64_TARBALL_FILE = "osquery-#{OSQUERY_VERSION}_1.linux_aarch64.tar.gz"
LINUX_AARCH64_TARBALL_PATH = File.join(DIR_TMP, LINUX_AARCH64_TARBALL_FILE)

file TARBALL_PATH => [DIR_TMP] do
    log "Downloading tarball.."
    response = URI.open("https://github.com/osquery/osquery/releases/download/#{OSQUERY_VERSION}/#{TARBALL_FILE}")
    File.write(TARBALL_PATH, response.read)
    verify_checksum(TARBALL_PATH)
end 

file LINUX_TARBALL_PATH => [DIR_TMP] do
    log "Downloading linux tarball.."
    response = URI.open("https://github.com/osquery/osquery/releases/download/#{OSQUERY_VERSION}/#{LINUX_TARBALL_FILE}")
    File.write(LINUX_TARBALL_PATH, response.read)
    verify_checksum(LINUX_TARBALL_PATH)
end

file LINUX_AARCH64_TARBALL_PATH => [DIR_TMP] do
    log "Downloading linux aarch64 tarball.."
    response = URI.open("https://github.com/osquery/osquery/releases/download/#{OSQUERY_VERSION}/#{LINUX_AARCH64_TARBALL_FILE}")
    File.write(LINUX_AARCH64_TARBALL_PATH, response.read)
    verify_checksum(LINUX_AARCH64_TARBALL_PATH)
end

OSQUERYD_PATH = File.join(DIR_TMP, "osqueryd")
OSQUERYD_LINUX_PATH = File.join(DIR_TMP, "osqueryd-linux")
OSQUERYD_LINUX_AARCH64_PATH = File.join(DIR_TMP, "osqueryd-linux-aarch64")

file OSQUERYD_PATH => [TARBALL_PATH] do
    log "Extracting tarball.."
    sh "tar -xvzf #{TARBALL_PATH} -C #{DIR_TMP}"
    sh "chmod +x #{OSQUERYD_PATH}"
end

file OSQUERYD_LINUX_PATH => [LINUX_TARBALL_PATH] do
    log "Extracting linux tarball.."
    # Extract into tmp; tarball contains usr/bin/osqueryd and opt/osquery/bin/osqueryd
    sh "tar -xvzf #{LINUX_TARBALL_PATH} -C #{DIR_TMP}"
    linux_usr_bin = File.join(DIR_TMP, "usr", "bin", "osqueryd")
    linux_opt_bin = File.join(DIR_TMP, "opt", "osquery", "bin", "osqueryd")
    source_bin = if File.exist?(linux_usr_bin)
        linux_usr_bin
    elsif File.exist?(linux_opt_bin)
        linux_opt_bin
    else
        raise "osqueryd not found after extracting linux tarball"
    end
    sh "cp #{source_bin} #{OSQUERYD_LINUX_PATH}"
    sh "chmod +x #{OSQUERYD_LINUX_PATH}"
end

file OSQUERYD_LINUX_AARCH64_PATH => [LINUX_AARCH64_TARBALL_PATH] do
    log "Extracting linux aarch64 tarball.."
    sh "tar -xvzf #{LINUX_AARCH64_TARBALL_PATH} -C #{DIR_TMP}"
    linux_usr_bin = File.join(DIR_TMP, "usr", "bin", "osqueryd")
    linux_opt_bin = File.join(DIR_TMP, "opt", "osquery", "bin", "osqueryd")
    source_bin = if File.exist?(linux_usr_bin)
        linux_usr_bin
    elsif File.exist?(linux_opt_bin)
        linux_opt_bin
    else
        raise "osqueryd not found after extracting linux aarch64 tarball"
    end
    sh "cp #{source_bin} #{OSQUERYD_LINUX_AARCH64_PATH}"
    sh "chmod +x #{OSQUERYD_LINUX_AARCH64_PATH}"
end

OSQUERYI_PATH = File.join(DIR_SIDECAR, "osqueryi")

file OSQUERYI_PATH => [OSQUERYD_PATH] do
    sh "mkdir -p #{DIR_SIDECAR}"
    sh "cp #{OSQUERYD_PATH} #{OSQUERYI_PATH}-aarch64-apple-darwin"
    sh "cp #{OSQUERYD_PATH} #{OSQUERYI_PATH}-x86_64-apple-darwin"
end

OSQUERYI_LINUX_X64_PATH = File.join(DIR_SIDECAR, "osqueryi-x86_64-unknown-linux-gnu")
OSQUERYI_LINUX_AARCH64_PATH = File.join(DIR_SIDECAR, "osqueryi-aarch64-unknown-linux-gnu")

file OSQUERYI_LINUX_X64_PATH => [OSQUERYD_LINUX_PATH] do
    sh "mkdir -p #{DIR_SIDECAR}"
    sh "cp #{OSQUERYD_LINUX_PATH} #{OSQUERYI_LINUX_X64_PATH}"
end

file OSQUERYI_LINUX_AARCH64_PATH => [OSQUERYD_LINUX_AARCH64_PATH] do
    sh "mkdir -p #{DIR_SIDECAR}"
    sh "cp #{OSQUERYD_LINUX_AARCH64_PATH} #{OSQUERYI_LINUX_AARCH64_PATH}"
end

task :clean do
    sh "rm -rf tmp"
    sh "rm -f src-tauri/vendor/osqueryi*"
end

task default: [OSQUERYI_PATH, OSQUERYI_LINUX_X64_PATH, OSQUERYI_LINUX_AARCH64_PATH]


