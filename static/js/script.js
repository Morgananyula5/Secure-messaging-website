function encryptMessage() {
    const message = document.getElementById('message').value;
    fetch('/encrypt', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ message: message })
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('encryptedMessage').innerText = data.encrypted_message;
        document.getElementById('key').innerText = data.key;
    })
    .catch(error => console.error('Error:', error));
}

function decryptMessage() {
    const encryptedMessage = document.getElementById('encryptedInput').value;
    const key = document.getElementById('keyInput').value;
    fetch('/decrypt', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ encrypted_message: encryptedMessage, key: key })
    })
    .then(response => response.json())
    .then(data => {
        if (data.decrypted_message) {
            document.getElementById('decryptedMessage').innerText = data.decrypted_message;
        } else {
            document.getElementById('decryptedMessage').innerText = 'Decryption failed';
        }
    })
    .catch(error => console.error('Error:', error));
}
