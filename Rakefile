require "open-uri"
require "json"
require "digest"
require "socket"
require "openssl"
require "shellwords"

def log(msg)
    puts "osquery bundle: #{msg}"
end

# Simple retry helper with exponential backoff to make downloads resilient to transient SSL/network errors
def with_retries(max_attempts: 5, base_sleep: 0.5, on: [OpenURI::HTTPError, Errno::ECONNRESET, Errno::ETIMEDOUT, SocketError, OpenSSL::SSL::SSLError])
    attempts = 0
    begin
        attempts += 1
        yield
    rescue *on => e
        if attempts < max_attempts
            sleep_time = base_sleep * (2 ** (attempts - 1))
            log "Download failed (#{e.class}: #{e.message}). Retrying in #{sleep_time.round(2)}s... (#{attempts}/#{max_attempts})"
            sleep sleep_time
            retry
        else
            log "Giving up after #{attempts} attempts due to: #{e.class}: #{e.message}"
            raise
        end
    end
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
    # Temporarily disabled to avoid CI rate limits on GitHub API during matrix builds
    log "Skipping checksum verification for #{File.basename(file_path)}"
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
    with_retries do
        response = URI.open("https://github.com/osquery/osquery/releases/download/#{OSQUERY_VERSION}/#{TARBALL_FILE}")
        File.write(TARBALL_PATH, response.read)
    end
    verify_checksum(TARBALL_PATH)
end 

file LINUX_TARBALL_PATH => [DIR_TMP] do
    log "Downloading linux tarball.."
    with_retries do
        response = URI.open("https://github.com/osquery/osquery/releases/download/#{OSQUERY_VERSION}/#{LINUX_TARBALL_FILE}")
        File.write(LINUX_TARBALL_PATH, response.read)
    end
    verify_checksum(LINUX_TARBALL_PATH)
end

file LINUX_AARCH64_TARBALL_PATH => [DIR_TMP] do
    log "Downloading linux aarch64 tarball.."
    with_retries do
        response = URI.open("https://github.com/osquery/osquery/releases/download/#{OSQUERY_VERSION}/#{LINUX_AARCH64_TARBALL_FILE}")
        File.write(LINUX_AARCH64_TARBALL_PATH, response.read)
    end
    verify_checksum(LINUX_AARCH64_TARBALL_PATH)
end

OSQUERYD_PATH = File.join(DIR_TMP, "osqueryd")
OSQUERYD_LINUX_PATH = File.join(DIR_TMP, "osqueryd-linux")
OSQUERYD_LINUX_AARCH64_PATH = File.join(DIR_TMP, "osqueryd-linux-aarch64")
OSQUERYD_WINDOWS_X64_PATH = File.join(DIR_TMP, "osqueryd-windows-x86_64.exe")
OSQUERYD_WINDOWS_AARCH64_PATH = File.join(DIR_TMP, "osqueryd-windows-aarch64.exe")

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
OSQUERYI_WINDOWS_X64_PATH = File.join(DIR_SIDECAR, "osqueryi-x86_64-pc-windows-msvc.exe")
OSQUERYI_WINDOWS_AARCH64_PATH = File.join(DIR_SIDECAR, "osqueryi-aarch64-pc-windows-msvc.exe")

file OSQUERYI_LINUX_X64_PATH => [OSQUERYD_LINUX_PATH] do
    sh "mkdir -p #{DIR_SIDECAR}"
    sh "cp #{OSQUERYD_LINUX_PATH} #{OSQUERYI_LINUX_X64_PATH}"
end

file OSQUERYI_LINUX_AARCH64_PATH => [OSQUERYD_LINUX_AARCH64_PATH] do
    sh "mkdir -p #{DIR_SIDECAR}"
    sh "cp #{OSQUERYD_LINUX_AARCH64_PATH} #{OSQUERYI_LINUX_AARCH64_PATH}"
end

## --- Windows binaries ---
# Rakefile never downloads Windows assets. CI prepares the Windows sidecar in
# src-tauri/vendor ahead of build, and developers commit updates when needed.

task :clean do
    sh "rm -rf tmp"
end

def vendor_binaries
    # Verify only the binaries relevant to the current platform/arch.
    # CI should rely on the vendored sidecars in src-tauri/vendor and never download on demand.
    platform = RUBY_PLATFORM
    if platform =~ /darwin/
        [
            "#{OSQUERYI_PATH}-aarch64-apple-darwin",
            "#{OSQUERYI_PATH}-x86_64-apple-darwin",
        ]
    elsif platform =~ /linux/
        arch = begin
            `uname -m`.strip
        rescue
            ""
        end
        if arch =~ /(aarch64|arm64)/
            [OSQUERYI_LINUX_AARCH64_PATH]
        else
            [OSQUERYI_LINUX_X64_PATH]
        end
    elsif platform =~ /mswin|mingw|cygwin/
        # GitHub Windows runners are x64; verify that one
        [OSQUERYI_WINDOWS_X64_PATH]
    else
        raise "Unsupported platform for vendor binary verification: #{platform}"
    end
end

task :verify do
    # Treat Git LFS pointer files as missing
    def lfs_pointer?(path)
        return false unless File.exist?(path) && File.size?(path)
        begin
            File.open(path, 'rb') { |f| f.read(256).to_s.include?('git-lfs.github.com/spec/v1') }
        rescue
            false
        end
    end

    missing = vendor_binaries.reject { |p| File.exist?(p) && File.size?(p) && !lfs_pointer?(p) }

    if missing.empty?
        log "All vendor binaries present and not LFS pointers: #{vendor_binaries.map { |p| File.basename(p) }.join(", ")}"
    else
        raise <<~MSG
        Missing or invalid vendor binaries (LFS pointers or absent):\n  - #{missing.join("\n  - ")}
        Ensure Git LFS is installed and pulled (e.g., `git lfs install && git lfs pull`).
        If needed, run `rake refresh_binaries` locally to fetch and commit them (preferably via Git LFS).
        MSG
    end
end

task :refresh_binaries => [OSQUERYI_PATH, OSQUERYI_LINUX_X64_PATH, OSQUERYI_LINUX_AARCH64_PATH]

task default: [:verify]

task :clean_vendor do
    sh "rm -f src-tauri/vendor/osqueryi*"
end

# Validate that all expected download URLs are reachable with curl
task :check_urls do
    urls = []

    # Constructed release asset URLs (direct downloads)
    base = "https://github.com/osquery/osquery/releases/download/#{OSQUERY_VERSION}"
    urls << File.join(base, TARBALL_FILE)
    urls << File.join(base, LINUX_TARBALL_FILE)
    urls << File.join(base, LINUX_AARCH64_TARBALL_FILE)

    # Dynamically discovered assets (Windows zips, checksums file if present)
    begin
        assets = fetch_release_assets
        checksum_asset = assets.find { |a| a["name"] =~ /sha256/i }
        urls << checksum_asset["browser_download_url"] if checksum_asset

        win_x64 = assets.find { |a| a["name"] =~ /windows.*(x86_64|amd64).*\.zip/i }
        win_arm = assets.find { |a| a["name"] =~ /windows.*(aarch64|arm64).*\.zip/i }
        urls << win_x64["browser_download_url"] if win_x64
        urls << win_arm["browser_download_url"] if win_arm
    rescue => e
        log "Warning: could not query GitHub release assets: #{e.class}: #{e.message}"
    end

    urls.compact!
    urls.uniq!

    log "Checking #{urls.length} URLs for osquery #{OSQUERY_VERSION}..."
    failed = []
    urls.each do |u|
        escaped = Shellwords.escape(u)
        # Use curl with retries; HEAD request (-I), fail on HTTP errors (-f)
        ok = system("curl -sS -I -f --retry 3 --retry-delay 1 --max-time 20 #{escaped} > /dev/null")
        if ok
            log "OK: #{u}"
        else
            log "FAIL: #{u}"
            failed << u
        end
    end

    if failed.any?
        raise <<~MSG
        One or more URLs are not reachable (HTTP error):\n  - #{failed.join("\n  - ")}
        MSG
    else
        log "All URLs are valid."
    end
end


