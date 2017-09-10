function loadPage() {
    dofoo();
}

function toHexString(byteArray) {
    return Array.from(byteArray, function(byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('')
}

function getMac(data)
{
    var enc = new TextEncoder("utf-8");
    var secret = enc.encode("YELLOW SUBMARINE");

    var byteData = data;
    if (typeof byteData === "string") {
        // Convert strings to bytes
        byteData = enc.encode(byteData);
    }

    return new Promise( (resolve,reject) => {
        
    window.crypto.subtle.importKey("raw", secret, "AES-CBC", false, ["encrypt", "decrypt"])
    .then( (key) => {
        var aescbc = { name: "AES-CBC", iv: new ArrayBuffer(16)};
        // In the Web Crypto API, the only padding mode that is supported is that of
        // PKCS#7
        window.crypto.subtle.encrypt(aescbc, key, byteData)
        .then( (result) => {
          
            var mac = new Uint8Array(result).slice(-16);
            console.log("mac " + toHexString(mac));
            resolve(toHexString(mac));
        })
        .catch( () => {console.warn('Error getting mac')
        });
    })
    .catch( () => {console.warn('Error creating key')
    });
    });
}

function dofoo() {
    getMac("alert('MZA who was that?');\n")
    .then( (mac) => {
        console.log( mac );
    });
} 

function updateAction(response)
{
    console.log("updateA " + response);
    
    const element = document.getElementById("btn_action");
    //element.addEventListener("click", forgotpass, false);
    element.setAttribute("onclick",response);
    console.log("onclick => " + response);
    // document.getElementById("").innerHTML = "Hello JavaScript!";
}

function loadGood() {
    getFile('./good.js')
    .then( updateAction(response) );
} 

function loadBad() {
    getFile('./bad.js')
    .then( updateAction(response) );
} 
function getFile(url)
{
    return new Promise(function (resolve, reject) {

        const xhr = new XMLHttpRequest();
        xhr.open('GET', url);

//        xhr.onreadystatechange = function() {
//            alert(client.responseText);
//        };

        xhr.onload = function() {
            if (this.status >= 200 && this.status < 300) {
                resolve(xhr.response);
            } else {
                reject({
                    status: this.status,
                    statusText: xhr.statusText
                });
            }
        };

        xhr.onerror = function () {
            reject({
                status: this.status,
                statusText: xhr.statusText
            });
        };

        xhr.onabort = function() {
            reject({
                status: this.status,
                statusText: xhr.statusText
            });
        };

        xhr.send();
    });
}