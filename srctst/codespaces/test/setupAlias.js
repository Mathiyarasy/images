import addAliases from 'esm-module-alias';
import path from 'path';
import { fileURLToPath } from 'url';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
console.log("__dirname", __dirname);
const abstractionsPath = path.resolve(__dirname, '../../out/src/abstractions/node');
console.log("Resolved path for @abstractions:", abstractionsPath);
addAliases({
    '@abstractions': abstractionsPath
});
// Verify that the alias is working by attempting to import a file
(async () => {
    try {
        const logFile = await import('@abstractions/logFile.js');
        console.log("Successfully imported logFile:", logFile);
    }
    catch (error) {
        console.error("Error importing logFile:", error);
    }
})();
//# sourceMappingURL=setupAlias.js.map