/**
 *  Hubitat - Panasonic IP Projector Driver  - 
 *
 *  Copyright 2024 VH - Vhorigian
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License. You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 *  for the specific language governing permissions and limitations under the License.
 *        
 *        1.0 15/2/2025  - V.BETA 1 - Power on / Power off Functions
 * 		  1.1 16/2/2025  - Added SendEvent for Switch
 *
 */
metadata {
    definition(name: "Panasonic IP Projector", namespace: "VH", author: "VH") {
        capability "Actuator"
        capability "Switch"

        command "sendPowerOffCommand"
        command "sendPowerOnCommand"
    }
}

preferences {
    section("Device Settings") {
        input "ipAddress", "text", title: "IP Address", required: true
        input "username", "text", title: "Username", defaultValue: "admin", required: true
        input "password", "password", title: "Password", required: true
        input name: "logEnable", type: "bool", title: "Enable debug logging", defaultValue: false
        input name: "UserGuide", type: "hidden", title: fmtHelpInfo("Manual do Driver")
    }
}

import groovy.transform.Field
@Field static final String DRIVER = "by TRATO"
@Field static final String USER_GUIDE = "https://github.com/hhorigian/"

String fmtHelpInfo(String str) {
    String prefLink = "<a href='${USER_GUIDE}' target='_blank'>${str}<br><div style='font-size: 70%;'>${DRIVER}</div></a>"
    return "<div style='font-size: 160%; font-style: bold; padding: 2px 0px; text-align: center;'>${prefLink}</div>"
}

import groovy.json.JsonSlurper
import groovy.transform.Field

def installed() {
    log.debug "Installed with settings: ${settings}"
    runIn(1800, logsOff)
}

def updated() {
    log.debug "Updated"
    initialize()
}

def initialize() {
    // Any initialization logic can go here
}

def parse(String description) {
    log.info "Parsing message: ${description}"
    // Handle any incoming messages that might affect the switch state
    // For example, if the projector sends a status update, you can parse it here
    // and update the switch state accordingly.
}

def on() {
    log.info "Turning on the projector"
    sendPowerOnCommand()
    sendEvent(name: "switch", value: "on")
}

def off() {
    log.info "Turning off the projector"
    sendPowerOffCommand()
    sendEvent(name: "switch", value: "off")
}

def sendPowerOffCommand() {
    def ip = ipAddress
    def user = username
    def pass = password
    def uri = "http://${ip}/cgi-bin/power_off.cgi"

    def authParams = getDigestAuthParams(uri)
    
    if (authParams) {
        def digestAuth = generateDigestAuth(uri, user, pass, authParams)
        
        if (digestAuth) {
            def headers = [
                "Authorization": digestAuth
            ]
            
            def params = [
                uri: uri,
                headers: headers
            ]
            
            try {
                httpGet(params) { resp ->
                    if (resp.status == 200) {
                        log.info "Power off command sent successfully."
                        sendEvent(name: "switch", value: "off")
                    } else {
                        log.error "Failed to send power off command. HTTP status: ${resp.status}"
                    }
                }
            } catch (Exception e) {
                log.error "Exception occurred while sending power off command: ${e.message}"
            }
        } else {
            log.error "Failed to generate Digest Authentication header."
        }
    } else {
        log.error "Failed to retrieve Digest Authentication parameters."
    }
}

def sendPowerOnCommand() {
    def ip = ipAddress
    def user = username
    def pass = password
    def uri = "http://${ip}/cgi-bin/power_on.cgi"

    def authParams = getDigestAuthParams(uri)
    
    if (authParams) {
        def digestAuth = generateDigestAuth(uri, user, pass, authParams)
        
        if (digestAuth) {
            def headers = [
                "Authorization": digestAuth
            ]
            
            def params = [
                uri: uri,
                headers: headers
            ]
            
            try {
                httpGet(params) { resp ->
                    if (resp.status == 200) {
                        log.info "Power ON command sent successfully."
                        sendEvent(name: "switch", value: "on")
                    } else {
                        log.error "Failed to send power ON command. HTTP status: ${resp.status}"
                    }
                }
            } catch (Exception e) {
                log.error "Exception occurred while sending power ON command: ${e.message}"
            }
        } else {
            log.error "Failed to generate Digest Authentication header."
        }
    } else {
        log.error "Failed to retrieve Digest Authentication parameters."
    }
}

private Map getDigestAuthParams(String uri) {
    def params = [:]
    try {
        httpGet([uri: uri]) { resp ->
            log.debug "Server response status: ${resp.status}"
            log.debug "Server response headers: ${resp.headers}"
        }
    } catch (groovyx.net.http.HttpResponseException e) {
        if (e.statusCode == 401) {
            def authHeader = e.response?.headers?.getAt("WWW-Authenticate")
            if (authHeader) {
                def authHeaderString = authHeader.toString()
                log.debug "WWW-Authenticate header: ${authHeaderString}"
                params.realm = extractValue(authHeaderString, "realm")
                params.nonce = extractValue(authHeaderString, "nonce")
                params.opaque = extractValue(authHeaderString, "opaque")
                params.qop = extractValue(authHeaderString, "qop")
            } else {
                log.error "WWW-Authenticate header not found in response."
            }
        } else {
            log.error "Server returned an unexpected status code: ${e.statusCode}"
        }
    } catch (Exception e) {
        log.error "Exception occurred while retrieving Digest Authentication parameters: ${e.message}"
    }
    return params
}

private String generateDigestAuth(String uri, String username, String password, Map authParams) {
    def realm = authParams.realm
    def nonce = authParams.nonce
    def opaque = authParams.opaque
    def qop = authParams.qop
    
    if (realm && nonce) {
        def ha1 = md5("${username}:${realm}:${password}")
        def ha2 = md5("GET:${uri}")
        def response = md5("${ha1}:${nonce}:${ha2}")
        
        return "Digest username=\"${username}\", realm=\"${realm}\", nonce=\"${nonce}\", uri=\"${uri}\", response=\"${response}\", opaque=\"${opaque}\""
    }
    return null
}

private String extractValue(String header, String key) {
    def pattern = ~/${key}="([^"]+)"/
    def matcher = pattern.matcher(header)
    if (matcher.find()) {
        return matcher.group(1)
    }
    return null
}

private String md5(String input) {
    return java.security.MessageDigest.getInstance("MD5").digest(input.bytes).encodeHex().toString()
}

def logsOff() {
    log.warn 'logging disabled...'
    device.updateSetting('logInfo', [value:'false', type:'bool'])
    device.updateSetting('logWarn', [value:'false', type:'bool'])
    device.updateSetting('logDebug', [value:'false', type:'bool'])
    device.updateSetting('logTrace', [value:'false', type:'bool'])
}

void logDebug(String msg) {
    if ((Boolean)settings.logDebug != false) {
        log.debug "${drvThis}: ${msg}"
    }
}

void logInfo(String msg) {
    if ((Boolean)settings.logInfo != false) {
        log.info "${drvThis}: ${msg}"
    }
}

void logTrace(String msg) {
    if ((Boolean)settings.logTrace != false) {
        log.trace "${drvThis}: ${msg}"
    }
}

void logWarn(String msg, boolean force = false) {
    if (force || (Boolean)settings.logWarn != false) {
        log.warn "${drvThis}: ${msg}"
    }
}

void logError(String msg) {
    log.error "${drvThis}: ${msg}"
}
