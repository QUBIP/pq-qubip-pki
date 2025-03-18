document.addEventListener("DOMContentLoaded", function () {
    const certForm = document.getElementById("certForm");
    const purpose = certForm.getAttribute("data-purpose");

    // actions after certificate generation
    const certActions = document.getElementById("certificate-actions");
    const downloadBtn = document.getElementById("download-cert-btn");
    const certContent = document.getElementById("certificate-content");
    const certText = document.getElementById("certText");

    // Create success message element
    const successMessage = document.createElement("p");
    successMessage.id = "success-message";
    successMessage.style.display = "none";
    successMessage.style.color = "green";
    successMessage.style.fontWeight = "bold";
    successMessage.textContent = "Certificate generated successfully!";
    certForm.parentNode.insertBefore(successMessage, certActions);

    // Handle checkboxes for tls-server certificate generation
    const fqdnCheckbox = document.getElementById("fqdnCheckbox");
    const ipCheckbox = document.getElementById("ipCheckbox");
    const fqdnInput = document.getElementById("fqdnInput");
    const ipInput = document.getElementById("ipInput");
    const fqdnError = document.getElementById("fqdnError");
    const ipError = document.getElementById("ipError");
    const clientIpError = document.getElementById("clientIpError");
    const clientInput = document.getElementById("clientIpInput");

    // Reset checkboxes and inputs on page load
    if (purpose == "tls-server") {
        fqdnCheckbox.checked = false;
        ipCheckbox.checked = false;
        fqdnInput.style.display = "none";
        fqdnInput.value = "";
        ipInput.style.display = "none";
        ipInput.value = "";


        fqdnCheckbox.addEventListener("change", function () {
            if (this.checked) {
                ipCheckbox.checked = false;
            }
            updateInputVisibility();
        });

        ipCheckbox.addEventListener("change", function () {
            if (this.checked) {
                fqdnCheckbox.checked = false;
            }
            updateInputVisibility();
        });

    }

    function updateInputVisibility() {
        if (purpose == "tls-client") {
            clientIpError.textContent = "";
        }
        if (fqdnCheckbox.checked) {
            fqdnInput.style.display = "inline-block";
            fqdnInput.required = true;
            fqdnError.textContent = "";
        } else {
            fqdnInput.style.display = "none";
            fqdnInput.value = "";
            fqdnInput.required = false;
            if (fqdnError.textContent != "") {
                fqdnError.textContent = "";
            }
        }

        if (ipCheckbox.checked) {
            ipInput.style.display = "inline-block";
            ipInput.required = true;
            ipError.textContent = "";
        } else {
            ipInput.style.display = "none";
            ipInput.value = "";
            ipInput.required = false;
            if (ipError.textContent != "") {
                ipError.textContent = "";
            }
        }
    }
    function validateInput() {
        let isValid = true;
        let cnType = null; // passed to flask 
        let commonName = null;

        const ipPattern = /^(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)$/;
        const fqdnPattern = /^(?!:\/\/)([a-zA-Z0-9-_]{1,63}\.)+[a-zA-Z]{2,6}$/;

        if (purpose == "tls-server") {
            // Validate FQDN
            if (fqdnCheckbox.checked) {
                ipError.textContent = "";
                if (!fqdnPattern.test(fqdnInput.value.trim())) {
                    fqdnError.textContent = "Invalid FQDN format.";
                    ipError.textContent = "";
                    isValid = false;
                }
                else {
                    fqdnError.textContent = "";
                    cnType = "fqdn";
                    commonName = fqdnInput.value.trim();
                }
            }
            // Validate IP
            if (ipCheckbox.checked) {
                fqdnError.textContent = "";
                if (!ipPattern.test(ipInput.value.trim())) {
                    ipError.textContent = "Invalid IP address format.";
                    isValid = false;
                } else {
                    ipError.textContent = "";
                    cnType = "ip";
                    commonName = ipInput.value.trim();
                }
            }
        }
        else {
            //client
            if (!ipPattern.test(clientInput.value.trim())) {
                clientIpError.textContent = "Invalid IP address format.";
                isValid = false;
            } else {
                clientIpError.textContent = "";
                cnType = "ip";
                commonName = clientInput.value.trim();
            }
        }
        if (!cnType) {
            isValid = false;
        }

        return { isValid, cnType, commonName };
    }


    // Handle form submission when generating a certificate
    document.getElementById("submitButton").addEventListener("click", function (event) {
        event.preventDefault();
        if (purpose == "code-signing") {
            // console.log('Form submitted');
            const data = {
                algorithm: document.getElementById('key_algorithm').value,
                commonName: "",
                cn_type: ""
            };
            // console.log(data);

            // Hide the "Generate Certificate" button once it's clicked
            const generateButton = document.querySelector('button[type="submit"]');
            generateButton.style.display = 'none';

            // Hide the form
            const formContainer = document.getElementById("certForm");
            formContainer.style.display = "none";

            fetch(`/generate_certificate/${purpose}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            })
                .then(response => response.json())
                .then(data => {
                    console.log('Certificate generation response: ', data);
                    const ca = data.ca;
                    const cert_id = data.certificate_id;
                    // show buttons
                    certActions.style.display = "flex";

                    // // Show the certificate content (if available)
                    // if (data.certificate) {
                    //     certContent.style.display = "block";
                    //     certText.textContent = data.certificate;
                    // }

                    // Show success message
                    successMessage.style.display = "block";

                    // Show buttons
                    certActions.style.display = "flex";

                    // Set up download button
                    let codesignCertificateDownloaded = false;
                    console.log(codesignCertificateDownloaded)
                    downloadBtn.addEventListener("click", function () {
                        if (codesignCertificateDownloaded) {
                            alert("The private key has been deleted for security reasons. Please generate another certificate if you need it.");
                            return; // Prevent further execution
                        }

                        // Show a confirmation popup before downloading
                        const userConfirmed = confirm("Warning: This certificate and private key can only be downloaded ONCE. After that, the private key will be deleted from the server. Do you want to proceed?");

                        if (!userConfirmed) return; // Stop if the user cancels
                        fetch(`/download_certificate/${data.ca}/${data.certificate_id}`, { method: 'GET' })
                            .then(response => {
                                if (!response.ok) throw new Error('Failed to download certificate');
                                return response.blob();
                            })
                            .then(blob => {
                                const link = document.createElement('a');
                                link.href = URL.createObjectURL(blob);
                                link.download = `${data.certificate_id}.zip`;
                                document.body.appendChild(link);
                                link.click();
                                document.body.removeChild(link);
                            })
                            .catch(error => {
                                console.error("Error downloading certificate:", error)
                                alert("Error: Failed to download certificate. It may have already been deleted.");
                            });
                    });
                })
                .catch(error => {
                    console.error("Error generating the certificate: ", error);
                });
        }
        else {

            // not code-signing
            const validation = validateInput();
            if (!validation.isValid) {
                return;
            }
            // console.log('Form submitted');
            const data = {
                algorithm: document.getElementById('key_algorithm').value,
                commonName: validation.commonName,
                cn_type: validation.cnType
            };

            // Hide the "Generate Certificate" button once it's clicked
            const generateButton = document.querySelector('button[type="submit"]');
            generateButton.style.display = 'none';
            // Hide the form
            const formContainer = document.getElementById("certForm");
            formContainer.style.display = "none";

            fetch(`/generate_certificate/${purpose}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            })
                .then(response => {
                    console.log(response.json())
                })
                .then(data => {
                    //console.log(data)

                    // show buttons
                    certActions.style.display = "flex";

                    // Show the certificate content (if available)
                    if (data.certificate) {
                        certContent.style.display = "block";
                        certText.textContent = data.certificate;
                    }

                    // Show success message
                    successMessage.style.display = "block";

                    // Show buttons
                    certActions.style.display = "flex";


                    // Set up download button
                    let certificateDownloaded = false;
                    console.log(certificateDownloaded)
                    downloadBtn.addEventListener("click", function () {
                        if (certificateDownloaded) {
                            alert("The private key has been deleted for security reasons. Please generate another certificate if you need it.");
                            return; // Prevent further execution
                        }
                    
                        // Show a confirmation popup before downloading
                        const userConfirmed = confirm("Warning: This certificate and private key can only be downloaded ONCE. After that, the private key will be deleted from the server. Do you want to proceed?");
                        
                        if (!userConfirmed) return; // Stop if the user cancels
                    
                        fetch(`/download_certificate/${data.ca}/${data.certificate_id}`, { method: 'GET' })
                            .then(response => {
                                if (!response.ok) throw new Error('Failed to download certificate');
                                return response.blob();
                            })
                            .then(blob => {
                                const link = document.createElement('a');
                                link.href = URL.createObjectURL(blob);
                                link.download = `${data.certificate_id}.zip`;
                                document.body.appendChild(link);
                                link.click();
                                document.body.removeChild(link);
                            })
                            .catch(error => {
                                console.error("Error downloading certificate:", error);
                                alert("Error: Failed to download certificate. It may have already been deleted.");
                            });
                    }); // end event download
                    
                })
                .catch(error => {
                    console.error("Error generating the certificate: ", error);
                });
                
            } // end not code signing
            const viewBtn = document.getElementById("view-cert-btn");
            const ca = this.getAttribute("data-ca");
            const certificate = this.getAttribute("data-cert");
            const filename = this.getAttribute("data-cert-filename");
            viewBtn.addEventListener("click", function () {
                console.log('Viewing certificate');
                console.log(ca);
                console.log(certificate);
                console.log(filename);
            });
    });


});
