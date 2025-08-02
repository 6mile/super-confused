#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const https = require('https');
const { promisify } = require('util');

const readFile = promisify(fs.readFile);
const readdir = promisify(fs.readdir);
const stat = promisify(fs.stat);

// ANSI color codes
const colors = {
    red: '\x1b[31m',
    reset: '\x1b[0m'
};

function colorize(text, color) {
    return colors[color] + text + colors.reset;
}

class SuperConfused {
    constructor(jsonMode = false) {
        this.results = [];
        this.jsonMode = jsonMode;
        this.supportedFiles = {
            'package.json': this.scanPackageJson,
            'requirements.txt': this.scanRequirementsTxt,
            'pyproject.toml': this.scanPyprojectToml,
            'go.mod': this.scanGoMod,
            'go.sum': this.scanGoSum,
            'Cargo.toml': this.scanCargoToml,
            'pom.xml': this.scanPomXml,
            'build.gradle': this.scanGradle,
            'composer.json': this.scanComposerJson,
            'Gemfile': this.scanGemfile,
            'yarn.lock': this.scanYarnLock,
            'package-lock.json': this.scanPackageLock,
            'bom.json': this.scanSbom,
            'sbom.json': this.scanSbom,
            'bom.xml': this.scanSbomXml,
            'sbom.xml': this.scanSbomXml
        };
    }

    async scan(targetPath) {
        if (!this.jsonMode) {
            console.log(`Scanning ${targetPath} for dependency confusion opportunities...`);
        }
        
        if (targetPath.startsWith('http://') || targetPath.startsWith('https://')) {
            await this.scanUrl(targetPath);
        } else {
            const isDirectory = (await stat(targetPath)).isDirectory();
            
            if (isDirectory) {
                await this.scanDirectory(targetPath);
            } else {
                await this.scanFile(targetPath);
            }
        }

        this.printResults();
        return this.results;
    }

    async scanUrl(url) {
        try {
            // Convert GitHub blob URLs to raw URLs
            let rawUrl = url;
            if (url.includes('github.com') && url.includes('/blob/')) {
                rawUrl = url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/');
            } else if (url.includes('gitlab.com') && url.includes('/blob/')) {
                rawUrl = url.replace('/blob/', '/raw/');
            }

            const content = await this.fetchUrl(rawUrl);
            const fileName = this.getFileNameFromUrl(url);
            
            if (this.supportedFiles[fileName]) {
                const scanner = this.supportedFiles[fileName].bind(this);
                await scanner(url, content);
            } else {
                if (!this.jsonMode) {
                    console.error(`Unsupported file type: ${fileName}`);
                }
            }
        } catch (error) {
            if (!this.jsonMode) {
                console.error(`Error fetching URL ${url}: ${error.message}`);
            }
        }
    }

    getFileNameFromUrl(url) {
        const pathname = new URL(url).pathname;
        const fileName = pathname.split('/').pop();
        return fileName;
    }

    fetchUrl(url) {
        return new Promise((resolve, reject) => {
            const request = https.get(url, { timeout: 10000 }, (response) => {
                if (response.statusCode === 200) {
                    let data = '';
                    response.on('data', chunk => {
                        data += chunk;
                    });
                    response.on('end', () => {
                        resolve(data);
                    });
                } else if (response.statusCode === 302 || response.statusCode === 301) {
                    // Handle redirects
                    this.fetchUrl(response.headers.location).then(resolve).catch(reject);
                } else {
                    reject(new Error(`HTTP ${response.statusCode}`));
                }
            });

            request.on('error', reject);
            request.on('timeout', () => {
                request.destroy();
                reject(new Error('Request timeout'));
            });
        });
    }

    async scanDirectory(dirPath) {
        try {
            const entries = await readdir(dirPath);
            
            for (const entry of entries) {
                const fullPath = path.join(dirPath, entry);
                const stats = await stat(fullPath);
                
                if (stats.isDirectory() && !entry.startsWith('.') && entry !== 'node_modules') {
                    await this.scanDirectory(fullPath);
                } else if (stats.isFile() && this.supportedFiles[entry]) {
                    await this.scanFile(fullPath);
                }
            }
        } catch (error) {
            if (!this.jsonMode) {
                console.error(`Error scanning directory ${dirPath}: ${error.message}`);
            }
        }
    }

    async scanFile(filePath) {
        const fileName = path.basename(filePath);
        
        if (!this.supportedFiles[fileName]) {
            return;
        }

        try {
            const content = await readFile(filePath, 'utf8');
            const scanner = this.supportedFiles[fileName].bind(this);
            await scanner(filePath, content);
        } catch (error) {
            if (!this.jsonMode) {
                console.error(`Error reading ${filePath}: ${error.message}`);
            }
        }
    }

    async scanPackageJson(filePath, content) {
        try {
            const packageData = JSON.parse(content);
            const dependencies = {
                ...packageData.dependencies,
                ...packageData.devDependencies,
                ...packageData.peerDependencies,
                ...packageData.optionalDependencies
            };

            for (const [name, version] of Object.entries(dependencies || {})) {
                if (this.isPotentiallyVulnerable(name)) {
                    const exists = await this.checkNpmPackageExists(name);
                    this.addResult(filePath, 'npm', name, version, exists);
                }
            }
        } catch (error) {
            if (!this.jsonMode) {
                console.error(`Error parsing package.json: ${error.message}`);
            }
        }
    }

    async scanPackageLock(filePath, content) {
        try {
            const lockData = JSON.parse(content);
            const dependencies = lockData.dependencies || {};
            
            for (const [name, info] of Object.entries(dependencies)) {
                if (this.isPotentiallyVulnerable(name)) {
                    const exists = await this.checkNpmPackageExists(name);
                    this.addResult(filePath, 'npm', name, info.version, exists);
                }
            }
        } catch (error) {
            if (!this.jsonMode) {
                console.error(`Error parsing package-lock.json: ${error.message}`);
            }
        }
    }

    async scanYarnLock(filePath, content) {
        const lines = content.split('\n');
        const packages = new Set();
        
        for (const line of lines) {
            const match = line.match(/^"?([^@\s]+)@/);
            if (match && this.isPotentiallyVulnerable(match[1])) {
                packages.add(match[1]);
            }
        }

        for (const packageName of packages) {
            const exists = await this.checkNpmPackageExists(packageName);
            this.addResult(filePath, 'npm', packageName, 'unknown', exists);
        }
    }

    async scanRequirementsTxt(filePath, content) {
        const lines = content.split('\n');
        
        for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed && !trimmed.startsWith('#')) {
                const packageMatch = trimmed.match(/^([a-zA-Z0-9\-_\.]+)/);
                if (packageMatch && this.isPotentiallyVulnerable(packageMatch[1])) {
                    const exists = await this.checkPyPiPackageExists(packageMatch[1]);
                    this.addResult(filePath, 'pypi', packageMatch[1], 'unknown', exists);
                }
            }
        }
    }

    async scanPyprojectToml(filePath, content) {
        const lines = content.split('\n');
        let inDependencies = false;
        let inOptionalDependencies = false;
        
        for (const line of lines) {
            const trimmed = line.trim();
            
            // Check for dependencies section
            if (trimmed === 'dependencies = [') {
                inDependencies = true;
                inOptionalDependencies = false;
                continue;
            }
            
            // Check for optional-dependencies section
            if (trimmed.includes('optional-dependencies') && trimmed.includes('[')) {
                inOptionalDependencies = true;
                inDependencies = false;
                continue;
            }
            
            // Check for end of section
            if (trimmed === ']' && (inDependencies || inOptionalDependencies)) {
                inDependencies = false;
                inOptionalDependencies = false;
                continue;
            }
            
            // Parse dependencies
            if ((inDependencies || inOptionalDependencies) && trimmed.includes('"')) {
                // Match patterns like "requests>=2.25.1" or "flask==2.0.0"
                const depMatch = trimmed.match(/"([a-zA-Z0-9\-_\.]+)/);
                if (depMatch && this.isPotentiallyVulnerable(depMatch[1])) {
                    const exists = await this.checkPyPiPackageExists(depMatch[1]);
                    this.addResult(filePath, 'pypi', depMatch[1], 'unknown', exists);
                }
            }
            
            // Also check for [project] dependencies format
            if (trimmed.startsWith('dependencies') && trimmed.includes('=') && trimmed.includes('[')) {
                // Handle single-line dependencies array
                const depsMatch = trimmed.match(/dependencies\s*=\s*\[(.*)\]/);
                if (depsMatch) {
                    const depsString = depsMatch[1];
                    const deps = depsString.split(',');
                    for (const dep of deps) {
                        const cleanDep = dep.trim().replace(/['"]/g, '');
                        const packageMatch = cleanDep.match(/^([a-zA-Z0-9\-_\.]+)/);
                        if (packageMatch && this.isPotentiallyVulnerable(packageMatch[1])) {
                            const exists = await this.checkPyPiPackageExists(packageMatch[1]);
                            this.addResult(filePath, 'pypi', packageMatch[1], 'unknown', exists);
                        }
                    }
                }
            }
        }
    }

    async scanSbom(filePath, content) {
        try {
            const sbomData = JSON.parse(content);
            
            // Detect SBOM format and extract components
            if (sbomData.bomFormat === 'CycloneDX') {
                await this.scanCycloneDx(filePath, sbomData);
            } else if (sbomData.spdxVersion) {
                await this.scanSpdx(filePath, sbomData);
            } else {
                // Try to auto-detect based on structure
                if (sbomData.components) {
                    await this.scanCycloneDx(filePath, sbomData);
                } else if (sbomData.packages) {
                    await this.scanSpdx(filePath, sbomData);
                }
            }
        } catch (error) {
            if (!this.jsonMode) {
                console.error(`Error parsing SBOM file: ${error.message}`);
            }
        }
    }

    async scanCycloneDx(filePath, sbomData) {
        const components = sbomData.components || [];
        
        for (const component of components) {
            if (component.name && component.type === 'library') {
                const packageName = component.name;
                const version = component.version || 'unknown';
                const ecosystem = this.detectEcosystemFromPurl(component.purl) || 'unknown';
                
                if (this.isPotentiallyVulnerable(packageName)) {
                    let exists = 'unknown';
                    
                    // Check package existence based on ecosystem
                    if (ecosystem === 'npm') {
                        exists = await this.checkNpmPackageExists(packageName);
                    } else if (ecosystem === 'pypi') {
                        exists = await this.checkPyPiPackageExists(packageName);
                    } else if (ecosystem === 'cargo') {
                        exists = await this.checkCratesIoPackageExists(packageName);
                    } else if (ecosystem === 'packagist') {
                        exists = await this.checkPackagistPackageExists(packageName);
                    } else if (ecosystem === 'gem') {
                        exists = await this.checkRubyGemsPackageExists(packageName);
                    }
                    
                    this.addResult(filePath, ecosystem, packageName, version, exists);
                }
            }
        }
    }

    async scanSpdx(filePath, sbomData) {
        const packages = sbomData.packages || [];
        
        for (const pkg of packages) {
            if (pkg.name && pkg.name !== sbomData.name) {
                const packageName = pkg.name;
                const version = pkg.versionInfo || 'unknown';
                const ecosystem = this.detectEcosystemFromSpdx(pkg) || 'unknown';
                
                if (this.isPotentiallyVulnerable(packageName)) {
                    let exists = 'unknown';
                    
                    // Check package existence based on ecosystem
                    if (ecosystem === 'npm') {
                        exists = await this.checkNpmPackageExists(packageName);
                    } else if (ecosystem === 'pypi') {
                        exists = await this.checkPyPiPackageExists(packageName);
                    } else if (ecosystem === 'cargo') {
                        exists = await this.checkCratesIoPackageExists(packageName);
                    } else if (ecosystem === 'packagist') {
                        exists = await this.checkPackagistPackageExists(packageName);
                    } else if (ecosystem === 'gem') {
                        exists = await this.checkRubyGemsPackageExists(packageName);
                    }
                    
                    this.addResult(filePath, ecosystem, packageName, version, exists);
                }
            }
        }
    }

    async scanSbomXml(filePath, content) {
        // Basic XML parsing for CycloneDX XML format
        const componentRegex = /<component[^>]*type="library"[^>]*>[\s\S]*?<name>([^<]+)<\/name>[\s\S]*?(?:<version>([^<]+)<\/version>)?[\s\S]*?(?:<purl>([^<]+)<\/purl>)?[\s\S]*?<\/component>/g;
        let match;
        
        while ((match = componentRegex.exec(content)) !== null) {
            const packageName = match[1];
            const version = match[2] || 'unknown';
            const purl = match[3];
            const ecosystem = this.detectEcosystemFromPurl(purl) || 'unknown';
            
            if (this.isPotentiallyVulnerable(packageName)) {
                let exists = 'unknown';
                
                // Check package existence based on ecosystem
                if (ecosystem === 'npm') {
                    exists = await this.checkNpmPackageExists(packageName);
                } else if (ecosystem === 'pypi') {
                    exists = await this.checkPyPiPackageExists(packageName);
                } else if (ecosystem === 'cargo') {
                    exists = await this.checkCratesIoPackageExists(packageName);
                } else if (ecosystem === 'packagist') {
                    exists = await this.checkPackagistPackageExists(packageName);
                } else if (ecosystem === 'gem') {
                    exists = await this.checkRubyGemsPackageExists(packageName);
                }
                
                this.addResult(filePath, ecosystem, packageName, version, exists);
            }
        }
    }

    detectEcosystemFromPurl(purl) {
        if (!purl) return null;
        
        if (purl.startsWith('pkg:npm/')) return 'npm';
        if (purl.startsWith('pkg:pypi/')) return 'pypi';
        if (purl.startsWith('pkg:cargo/')) return 'cargo';
        if (purl.startsWith('pkg:composer/')) return 'packagist';
        if (purl.startsWith('pkg:gem/')) return 'gem';
        if (purl.startsWith('pkg:maven/')) return 'maven';
        if (purl.startsWith('pkg:golang/')) return 'go';
        
        return null;
    }

    detectEcosystemFromSpdx(pkg) {
        // Try to detect ecosystem from SPDX package info
        const downloadLocation = pkg.downloadLocation || '';
        const packageFileName = pkg.packageFileName || '';
        const homepage = pkg.homepage || '';
        
        if (downloadLocation.includes('npmjs.org') || packageFileName.includes('.tgz')) {
            return 'npm';
        }
        if (downloadLocation.includes('pypi.org') || downloadLocation.includes('files.pythonhosted.org')) {
            return 'pypi';
        }
        if (downloadLocation.includes('crates.io')) {
            return 'cargo';
        }
        if (downloadLocation.includes('packagist.org')) {
            return 'packagist';
        }
        if (downloadLocation.includes('rubygems.org')) {
            return 'gem';
        }
        if (downloadLocation.includes('maven') || packageFileName.includes('.jar')) {
            return 'maven';
        }
        
        return null;
    }

    async scanGoMod(filePath, content) {
        const lines = content.split('\n');
        
        for (const line of lines) {
            const trimmed = line.trim();
            const requireMatch = trimmed.match(/^\s*([^\s]+)\s+v/);
            
            if (requireMatch) {
                const moduleName = requireMatch[1];
                if (this.isPotentiallyVulnerable(moduleName)) {
                    this.addResult(filePath, 'go', moduleName, 'unknown', 'unknown');
                }
            }
        }
    }

    async scanGoSum(filePath, content) {
        const lines = content.split('\n');
        const modules = new Set();
        
        for (const line of lines) {
            const parts = line.split(' ');
            if (parts.length >= 2) {
                const modulePath = parts[0].split('/v')[0];
                if (this.isPotentiallyVulnerable(modulePath)) {
                    modules.add(modulePath);
                }
            }
        }

        for (const moduleName of modules) {
            this.addResult(filePath, 'go', moduleName, 'unknown', 'unknown');
        }
    }

    async scanCargoToml(filePath, content) {
        const lines = content.split('\n');
        let inDependencies = false;
        
        for (const line of lines) {
            const trimmed = line.trim();
            
            if (trimmed === '[dependencies]' || trimmed === '[dev-dependencies]') {
                inDependencies = true;
                continue;
            }
            
            if (trimmed.startsWith('[') && trimmed !== '[dependencies]' && trimmed !== '[dev-dependencies]') {
                inDependencies = false;
                continue;
            }
            
            if (inDependencies && trimmed.includes('=')) {
                const packageMatch = trimmed.match(/^([a-zA-Z0-9\-_]+)\s*=/);
                if (packageMatch && this.isPotentiallyVulnerable(packageMatch[1])) {
                    const exists = await this.checkCratesIoPackageExists(packageMatch[1]);
                    this.addResult(filePath, 'crates.io', packageMatch[1], 'unknown', exists);
                }
            }
        }
    }

    async scanComposerJson(filePath, content) {
        try {
            const composerData = JSON.parse(content);
            const dependencies = {
                ...composerData.require,
                ...composerData['require-dev']
            };

            for (const [name, version] of Object.entries(dependencies || {})) {
                if (name !== 'php' && this.isPotentiallyVulnerable(name)) {
                    const exists = await this.checkPackagistPackageExists(name);
                    this.addResult(filePath, 'packagist', name, version, exists);
                }
            }
        } catch (error) {
            if (!this.jsonMode) {
                console.error(`Error parsing composer.json: ${error.message}`);
            }
        }
    }

    async scanGemfile(filePath, content) {
        const lines = content.split('\n');
        
        for (const line of lines) {
            const trimmed = line.trim();
            const gemMatch = trimmed.match(/gem\s+['"]([^'"]+)['"]/);
            
            if (gemMatch && this.isPotentiallyVulnerable(gemMatch[1])) {
                const exists = await this.checkRubyGemsPackageExists(gemMatch[1]);
                this.addResult(filePath, 'rubygems', gemMatch[1], 'unknown', exists);
            }
        }
    }

    async scanPomXml(filePath, content) {
        const dependencyRegex = /<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>/g;
        let match;
        
        while ((match = dependencyRegex.exec(content)) !== null) {
            const groupId = match[1];
            const artifactId = match[2];
            const fullName = `${groupId}:${artifactId}`;
            
            if (this.isPotentiallyVulnerable(artifactId)) {
                this.addResult(filePath, 'maven', fullName, 'unknown', 'unknown');
            }
        }
    }

    async scanGradle(filePath, content) {
        const lines = content.split('\n');
        
        for (const line of lines) {
            const trimmed = line.trim();
            const depMatch = trimmed.match(/(?:implementation|compile|api|testImplementation)\s+['"]([^'"]+)['"]/);
            
            if (depMatch) {
                const parts = depMatch[1].split(':');
                if (parts.length >= 2) {
                    const artifactId = parts[1];
                    if (this.isPotentiallyVulnerable(artifactId)) {
                        this.addResult(filePath, 'maven', depMatch[1], 'unknown', 'unknown');
                    }
                }
            }
        }
    }

    isPotentiallyVulnerable(packageName) {
        if (packageName.includes('://') || packageName.startsWith('git+')) {
            return false;
        }
        
        // For scoped packages, we still want to check them, but with different logic
        if (packageName.startsWith('@')) {
            // Only check scoped packages that look suspicious
            const scopedSuspiciousPatterns = [
                /^@[a-z]+\/[a-z]{3,8}$/,  // short package names in scope
                /^@[a-z]+\/(lib|utils?|helper|common|core|base|tools?|sdk)$/i,  // generic names
                /^@[a-z]+\/(test|demo|example|sample)[-_]?/i,  // test/demo packages
            ];
            return scopedSuspiciousPatterns.some(pattern => pattern.test(packageName));
        }
        
        const suspiciousPatterns = [
            /^[a-z]+[-_][a-z]+$/,
            /^[a-z]{3,8}$/,
            /^(lib|utils?|helper|common|core|base|tools?|sdk)$/i,
            /^(test|demo|example|sample)[-_]?/i,
        ];

        const wellKnownPackages = [
            'react', 'vue', 'angular', 'lodash', 'express', 'axios', 'moment',
            'jquery', 'bootstrap', 'webpack', 'babel', 'eslint', 'jest', 'mocha',
            'typescript', 'commander', 'chalk', 'inquirer', 'yargs', 'fs-extra',
            'rimraf', 'glob', 'mkdirp', 'debug', 'semver', 'uuid', 'cors',
            'dotenv', 'nodemon', 'concurrently', 'cross-env', 'husky', 'lint-staged'
        ];

        if (wellKnownPackages.includes(packageName.toLowerCase())) {
            return false;
        }

        return suspiciousPatterns.some(pattern => pattern.test(packageName)) || 
               packageName.length <= 4;
    }

    async checkNpmPackageExists(packageName) {
        const encodedPackageName = packageName.startsWith('@') 
            ? packageName.replace('@', '%40')
            : packageName;
            
        return this.makeHttpRequest(`https://registry.npmjs.org/${encodedPackageName}`)
            .then(() => true)
            .catch(() => false);
    }

    async checkPyPiPackageExists(packageName) {
        return this.makeHttpRequest(`https://pypi.org/pypi/${packageName}/json`)
            .then(() => true)
            .catch(() => false);
    }

    async checkCratesIoPackageExists(packageName) {
        return this.makeHttpRequest(`https://crates.io/api/v1/crates/${packageName}`)
            .then(() => true)
            .catch(() => false);
    }

    async checkPackagistPackageExists(packageName) {
        return this.makeHttpRequest(`https://packagist.org/packages/${packageName}.json`)
            .then(() => true)
            .catch(() => false);
    }

    async checkRubyGemsPackageExists(packageName) {
        return this.makeHttpRequest(`https://rubygems.org/api/v1/gems/${packageName}.json`)
            .then(() => true)
            .catch(() => false);
    }

    makeHttpRequest(url) {
        return new Promise((resolve, reject) => {
            const request = https.get(url, { timeout: 5000 }, (response) => {
                if (response.statusCode === 200) {
                    resolve(response);
                } else {
                    reject(new Error(`Status: ${response.statusCode}`));
                }
            });

            request.on('error', reject);
            request.on('timeout', () => {
                request.destroy();
                reject(new Error('Request timeout'));
            });
        });
    }

    addResult(filePath, ecosystem, packageName, version, exists) {
        const risk = exists === false ? 'HIGH' : exists === true ? 'LOW' : 'UNKNOWN';
        
        this.results.push({
            file: filePath,
            ecosystem,
            package: packageName,
            version,
            exists,
            risk
        });
    }

    printResults() {
        if (this.jsonMode) {
            const vulnerabilities = this.results
                .filter(r => r.risk === 'HIGH' || r.risk === 'UNKNOWN');
            
            if (vulnerabilities.length > 0) {
                const packages = vulnerabilities.map(result => ({
                    [result.package]: result.version
                }));

                const output = {
                    "name": "super-confused",
                    "description": "Identify dependency confusion in your source code",
                    "author": "6mile",
                    "dependency-confused-packages": packages
                };

                console.log(JSON.stringify(output, null, 2));
            }
            return;
        }

        const highRisk = this.results.filter(r => r.risk === 'HIGH');
        const unknownRisk = this.results.filter(r => r.risk === 'UNKNOWN');

        if (highRisk.length === 0 && unknownRisk.length === 0) {
            return;
        }

        highRisk.forEach(result => {
            console.log(`${result.package} (${result.ecosystem}) in ${result.file}`);
            console.log(`Version: ${result.version}`);
            console.log(colorize('This package may not exist in the public registry!', 'red'));
            console.log('');
        });

        unknownRisk.forEach(result => {
            console.log(`${result.package} (${result.ecosystem}) in ${result.file}`);
            console.log(`Version: ${result.version}`);
            console.log('Manual verification recommended');
            console.log('');
        });
    }
}

async function main() {
    const args = process.argv.slice(2);
    let jsonMode = false;
    let targetPath;

    if (args.includes('--json')) {
        jsonMode = true;
        targetPath = args.find(arg => arg !== '--json');
    } else {
        targetPath = args[0];
    }
    
    if (!targetPath) {
        console.log('Usage: super-confused [--json] <path|url>');
        console.log('');
        console.log('Examples:');
        console.log('  super-confused ./package.json');
        console.log('  super-confused --json ./my-project');
        console.log('  super-confused https://github.com/user/repo/blob/main/package.json');
        console.log('  super-confused .');
        process.exit(1);
    }
    
    if (!targetPath.startsWith('http://') && !targetPath.startsWith('https://') && !fs.existsSync(targetPath)) {
        if (!jsonMode) {
            console.error(`Path does not exist: ${targetPath}`);
        }
        process.exit(1);
    }

    const scanner = new SuperConfused(jsonMode);
    
    try {
        await scanner.scan(targetPath);
    } catch (error) {
        if (!jsonMode) {
            console.error(`Scan failed: ${error.message}`);
        }
        process.exit(1);
    }
}

module.exports = SuperConfused;

if (require.main === module) {
    main().catch(console.error);
}
