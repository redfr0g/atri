async function uploadBlob(blob) {
    const url = '/reports/images/upload';

    try {
        const formData = new FormData();
        formData.append('file', blob, 'filename.png');

        const response = await fetch(url, {
            method: 'POST',
            body: formData
        });

        if (response.ok) {
            console.log('Blob uploaded successfully!');
            const result = await response.text();
            return result
        } else {
            console.error('Failed to upload Blob:', response.statusText);
        }
    } catch (error) {
        console.error('Error:', error);
    }
}

for (let i = 0; i < editors.length; i++) {
    editors[i].codemirror.on("paste", async function (codemirror, event) {
        
        if ((event.clipboardData.files).length == 0) {
            return
        }

        event.preventDefault();
        
        for (const file of event.clipboardData.files) {
            let uuid = await uploadBlob(file);
            codemirror.replaceSelection("![image](/reports/images/" + uuid + ")");
          }
    
        }); }