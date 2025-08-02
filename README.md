![super-confused](super-confused-github-banner.png)

# super-confused

A next-gen dependency confusion analysis tool that identifies confusion opportunities in source code and SBOM files.
super-confused works on multiple package manifest and SBOM file formats, either locally, or remotely.

I've been using [Confused](https://github.com/visma-prodsec/confused) for years, but really wanted a tool that supported more languages and SBOMs.  Also, I wanted to refactor this in Javascript so I can publish it as an NPM package.  So, super-confused was born!

## Features

- **17 file format support**: package.json, requirements.txt, pyproject.toml, go.mod, Cargo.toml, composer.json, Gemfile, pom.xml, build.gradle, yarn.lock, package-lock.json, bom.json, sbom.json, bom.xml, sbom.xml, go.sum
- **Remote scanning**: Scan files directly from GitHub/GitLab URLs
- **SBOM support**: CycloneDX and SPDX formats (JSON/XML)
- **Real-time verification**: Checks package existence across public registries
- **JSON output**: Machine-readable results for CI/CD integration

## Installation

```bash
git clone https://github.com/6mile/super-confused.git
cd super-confused
chmod +x super-confused.js
```

## Usage

```bash
# Scan local file
./super-confused.js package.json

# Scan directory
./super-confused.js .

# Scan remote file
./super-confused.js https://github.com/user/repo/blob/main/package.json

# JSON output
./super-confused.js --json package.json
```

## Output

**Standard mode** shows detailed vulnerability information with risk levels:
```bash
Scanning ./package.json for dependency confusion opportunities...
@your-company/internal-package-frontend (npm) in ./package.json
Version: 1.0.0
This package may not exist in the public registry!

@your-company/internal-package-infrastructure (npm) in ./package.json
Version: 1.0.0
This package may not exist in the public registry!

private-package (npm) in ./package.json
Version: ^2.903.0
This package may not exist in the public registry!
```

**JSON mode** outputs structured data:
```json
{
  "name": "super-confused",
  "description": "Identify dependency confusion opportunities in source code and SBOM files.",
  "author": "6mile",
  "dependency-confused-packages": [
    {
      "@yourcompany/internal-package": "1.0.0"
    }
  ]
}
```

## Supported Ecosystems

- npm (Node.js)
- PyPI (Python)
- Cargo (Rust)
- Packagist (PHP)
- RubyGems (Ruby)
- Maven (Java)
- Go modules

## Author

Created by 6mile
