
import { logMessage } from '#vscode-abstractions/logFile.js';


export function callLogMessage() {
	console.log('Calling logMessage from extension2');
	return logMessage();
}

callLogMessage();