'use strict';

/* const gulp = require('gulp');
const path = require('path');
const fs = require('fs');
const readline = require('readline');
const webpackStream = require('webpack-stream');
const moment = require('moment');
const webPackProdConfig = require('./webpack/webpack.prod.js');
const webpackDevConfig = require('./webpack/webpack.dev.js');
const [webpackNodeBundleAnalyzer, webpackBrowserBundleAnalyzer] = require('./webpack/webpack.bundleAnalyzer.js');
const child_process = require('child_process');
const gulpTypescript = require('gulp-typescript');
const sourcemaps = require('gulp-sourcemaps');
const utils = require('../common/utils'); */

import gulp from 'gulp';
import path, { dirname } from 'path';
import fs from 'fs';
import * as readline from 'readline';
import webpackStream from 'webpack-stream';
import moment from 'moment';
//import { webPackProdConfig } from './webpack/webpack.prod.js';
//import webpackDevConfig from './webpack/webpack.dev.js';
//import { webpackNodeBundleAnalyzer, webpackBrowserBundleAnalyzer } from './webpack/webpack.bundleAnalyzer.js';
import child_process from 'child_process';
import gulpTypescript from 'gulp-typescript';
import sourcemaps from 'gulp-sourcemaps';
import utils from '../common/utils.js';
import { fileURLToPath } from 'url';
import { readFile } from 'fs/promises';


const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const testResultsDir = path.join(__dirname, 'out', 'testresults');


const srcDir = path.join(__dirname, 'debug', 'src');

gulp.task('copy-devcontainer-cli-spec-node', function () {
    return gulp
        .src(['../node_modules/@microsoft/vscode-devcontainerjson-support/dist/spec-node/**'])
        .pipe(gulp.dest('./dist/spec-node'));
});

gulp.task('copy-json-files', function () {
    return gulp.src([path.join(__dirname, 'package.*'), path.join(__dirname, 'titles.json')]).pipe(gulp.dest('debug'));
});

gulp.task('copy-images', function () {
    return gulp.src([path.join(__dirname, 'images/**/*')]).pipe(gulp.dest(path.join(__dirname, 'debug', 'images')));
});

gulp.task(
    'prepare-debug',
    gulp.series('copy-json-files', 'copy-images', async function () {
        console.log('Preparing debug');
        const packageJsonPath = path.join(__dirname, 'debug', 'package.json');
        console.log('packageJsonPath', packageJsonPath);
        const packageJson = JSON.parse(await readFile(packageJsonPath, 'utf8'));
        packageJson.main = './src/extension.js';
        packageJson.aliases['@abstractions'] = './src/abstractions/node';
        packageJson.aliases['@vscode-abstractions'] =
            '../../node_modules/@vs/vscode-command-framework/dist/src/abstractions/node';
        packageJson.aliases['@grpc-node-client'] = '../../node_modules/@vs/grpc/dist/src/clients/node';
        packageJson.aliases['@grpc-browser-client'] = '../../node_modules/@vs/grpc/dist/src/clients/browser';
        let jsonString = JSON.stringify(packageJson, null, '\t');
        jsonString = jsonString.replace(/images\//g, '../images/');

        fs.writeFileSync(packageJsonPath, jsonString, 'utf8');

        const tsProject = gulpTypescript.createProject('tsconfig.json');
        const jsFiles = tsProject.src().pipe(sourcemaps.init()).pipe(tsProject());
        console.log('COMPLETED DEBUG TASKS')
        return jsFiles
            .pipe(
                sourcemaps.write('.', {
                    includeContent: false,
                    sourceRoot: path.join(__dirname, 'out'),
                }),
            )
            .pipe(gulp.dest('debug'));

    }),
);

gulp.task('inject-module-alias', async function () {
    console.log('inject-module-alias TASK');

    const moduleAliasPath = path.join(srcDir, 'moduleAliasInject.js');
    const extensionPath = path.join(srcDir, 'extension.js');
    const extension = fs.readFileSync(extensionPath, 'utf8');

    // Remove CR, LF, "use strict", and the source map suffix from contents of moduleAliasInject.js.
    const moduleAlias = fs
        .readFileSync(moduleAliasPath, 'utf8')
        .replace(/[\r\n]+/g, '')
        .replace('"use strict";', '')
        .replace('//# sourceMappingURL=moduleAliasInject.js.map', '');

    const marker =
        '// DO NOT REMOVE OR CHANGE THIS LINE - inject-module-alias in gulpfile.js replaces it by contents of moduleAliasInject.js in local debugging';
    if (!extension.includes(marker)) {
        throw new Error(`Cannot find module alias marker in '${extensionPath}'`);
    }

    const newExtension = extension.replace(marker, moduleAlias);
    fs.writeFileSync(extensionPath, newExtension, 'utf8');
});

gulp.task('inject-hub-constants', function () {
    const hubContantsJs = path.join(__dirname, '../workspace/client-vscode/dist/src/hubConstants.js');
    return utils.replaceFileContent(hubContantsJs, function (content) {
        content = content.replace('port-forwarder-hub.js', '../../port-forwarder/hub/out/app.js');
        return content;
    });
});

gulp.task('compile-debug', async function () {
    return gulp.series('prepare-debug', 'inject-module-alias', 'inject-hub-constants')();
});

gulp.task('start-watcher', function () {
    return gulp.watch(['./src/**/*', './extension-tests/**/*'], { ignoreInitial: false }, gulp.series('compile-debug'));
});

/* gulp.task('analyze-node', function () {
    return gulp
        .src('./src/extension.ts')
        .pipe(webpackStream(webpackNodeBundleAnalyzer))
        .pipe(gulp.dest('./out/bundle'));
}); */

/* gulp.task('analyze-browser', function () {
    return gulp
        .src('./src/extension.ts')
        .pipe(webpackStream(webpackBrowserBundleAnalyzer))
        .pipe(gulp.dest('./out/bundle'));
}); */

gulp.task('analyze-node', async () => {
    const { default: webpackNodeBundleAnalyzer } = await import('./webpack/webpack.bundleAnalyzer.js');
    return gulp
        .src('./src/extension.ts')
        .pipe(webpackStream(webpackNodeBundleAnalyzer))
        .pipe(gulp.dest('./out/bundle'));
});

gulp.task('analyze-browser', async () => {
    const { default: webpackBrowserBundleAnalyzer } = await import('./webpack/webpack.bundleAnalyzer.js');
    return gulp
        .src('./src/extension.ts')
        .pipe(webpackStream(webpackBrowserBundleAnalyzer))
        .pipe(gulp.dest('./out/bundle'));
});

gulp.task('grpc', async () => {
    const commandPath = path.join(__dirname, '..', 'grpc', 'src', 'proto');
    console.log('Starting grpc task');
    let command;
    if (process.platform === 'win32') {
        command = utils.executeCommand(commandPath, 'powershell.exe .\\protoc.ps1');
    } else {
        command = utils.executeCommand(commandPath, './protoc.sh');
    }

    command
        .then(() => {
            console.log('Finished grpc task successfully');
            return command;
        })
        .catch((error) => {
            console.error('Error in grpc task:', error);
        });
});

gulp.task('tsc', (done) => {
    let command;
    console.log('Starting tsc task');
    command = utils.executeCommand(__dirname, '../common/node_modules/.bin/tsc -b ./');
    command
        .then(() => {
            console.log('Finished tsc task successfully');
            done();
        })
        .catch((error) => {
            console.error('Error in tsc task:', error);
            done(error);
        });
});

/* gulp.task('webpack-dev', function () {
    return gulp
        .src('./src/extension.ts')
        .pipe(webpackStream({ config: webpackDevConfig }))
        .pipe(gulp.dest('./out/bundle'));
}); */

gulp.task('webpack-dev', async () => {
    const { default: webpackDevConfig } = await import('./webpack/webpack.dev.js');
    return gulp
        .src('./src/extension.ts')
        .pipe(webpackStream({ config: webpackDevConfig }))
        .pipe(gulp.dest('./out/bundle'));
});

/* gulp.task('webpack-prod', function () {
    return gulp
        .src('./src/extension.ts')
        .pipe(webpackStream({ config: webPackProdConfig }))
        .pipe(gulp.dest('./out/bundle'));
}); */

gulp.task('webpack-prod', async () => {
    const { default: webPackProdConfig } = await import('./webpack/webpack.prod.js');
    return gulp
        .src('./src/extension.ts')
        .pipe(webpackStream({ config: webPackProdConfig }))
        .pipe(gulp.dest('./out/bundle'));
});

gulp.task('compile-internal', gulp.series('grpc', gulp.parallel('copy-devcontainer-cli-spec-node', 'tsc')));

gulp.task('compile-prod', gulp.series('compile-internal', 'webpack-prod'));

gulp.task(
    'compile-dev-watch',
    gulp.series('grpc', gulp.parallel('copy-devcontainer-cli-spec-node', 'tsc'), 'webpack-dev'),
);

async function mkdirp(dir) {
    fs.mkdir(dir, function (error) {
        if (error && error.code !== 'EEXIST') {
            throw error;
        }
    });
}

function executeCommand(cwd, command, args) {
    return new Promise(function (resolve, reject) {
        const p = child_process.execFile(command, args, { cwd: cwd }, (err) => {
            if (err) {
                err.showStack = false;
                reject(err);
            }
            resolve();
        });
        p.stdout.pipe(process.stdout);
        p.stderr.pipe(process.stderr);
    });
}

gulp.task('test', async () => {
    await mkdirp(testResultsDir);

    const testResultsFile = path.join(testResultsDir, `cloudenv_${moment().format('YYYY-MM-DD_HH-mm-ss-SSS')}.trx`);
    const reporterConfig = {
        reporterEnabled: 'spec, @vs/mocha-trx-reporter',
        vsMochaTrxReporterReporterOptions: {
            output: testResultsFile,
        },
    };
    const reporterConfigFile = path.join(testResultsDir, 'mocha-multi-reporters.config');
    fs.writeFile(reporterConfigFile, JSON.stringify(reporterConfig), function (error) {
        if (error) throw error;
    });

    try {
        await executeCommand(__dirname, 'npm', [
            'run',
            '--silent',
            'test:mocha',
            '--',
            '--reporter',
            'mocha-multi-reporters',
            '--reporter-options',
            `configFile=${reporterConfigFile}`,
        ]);
    } finally {
        fs.unlink(reporterConfigFile, function (error) {
            if (error) throw error;
        });
    }
});

gulp.task('update-devcontainer-wizard', async () => {
    child_process.exec(
        'npm pack @microsoft/vscode-devcontainerjson-support --registry=https://npm.pkg.github.com',
        (error, packageFile) => {
            if (error) {
                throw error;
            }
            const registryUri = 'https://devdiv.pkgs.visualstudio.com/_packaging/NodeRepos/npm/registry/';
            executeCommand(__dirname, 'npm', ['publish', `--registry ${registryUri}`, `${packageFile}`]);
        },
    );
});

gulp.task('webpack-port-forwarder', function () {
    return utils.executeCommand(path.join(__dirname, '../port-forwarder/hub/'), 'yarn webpack-node');
});

gulp.task('copy-port-forwarder', function () {
    return gulp.src(['../port-forwarder/hub/out-node/port-forwarder-hub.js']).pipe(gulp.dest(`./`));
});

gulp.task('deploy-port-forwarder', gulp.series('webpack-port-forwarder', 'copy-port-forwarder'));

gulp.task('package', gulp.series('compile-internal', gulp.parallel('webpack-prod', 'deploy-port-forwarder')));

gulp.task('bump-version', async () => {
    // Bump the patch version
    await executeCommand(__dirname, 'yarn', ['version', '--patch', '--no-git-tag-version']);

    // Load the new version from the updated package.json file
    const packageJsonPath = path.join(__dirname, 'package.json');
    const packageJson = require(packageJsonPath);
    const version = packageJson.version;

    // Update changelog with new version section
    const changelogPath = path.join(__dirname, 'CHANGELOG.MD');
    const fileStream = fs.createReadStream(changelogPath);

    const oldLines = readline.createInterface({
        input: fileStream,
        crlfDelay: Infinity,
    });
    const newLines = [];

    let added = false;
    for await (const line of oldLines) {
        newLines.push(line);

        if (!added && line === '') {
            // Insert the new section after the first blank line at the top of the changelog
            newLines.push(`# ${version}`);
            newLines.push('* Bug fixes');
            newLines.push('');

            added = true;
        }
    }

    fs.writeFileSync(changelogPath, newLines.join('\n'));
});
