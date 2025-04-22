document.addEventListener("DOMContentLoaded", function () {

    let certificateDownloaded = false;
    let latestCertInfo = null;
    const certForm = document.getElementById("certForm");
    const chain = certForm.getAttribute("data-chain");
    const purpose = certForm.getAttribute("data-purpose");

    // Actions after certificate generation
    const certActions = document.getElementById("certificate-actions");
    const downloadBtn = document.getElementById("download-cert-btn");
    const certContent = document.getElementById("certificate-content");
    const certText = document.getElementById("certText");

    // Common Name fields (Handles both tls-server and tls-client)
    const fqdnCheckboxes = document.querySelectorAll(".fqdn-checkbox");
    const ipCheckboxes = document.querySelectorAll(".ip-checkbox");
    const fqdnInputs = document.querySelectorAll(".fqdn-input");
    const ipInputs = document.querySelectorAll(".ip-input");
    const fqdnErrors = document.querySelectorAll(".fqdn-error");
    const ipErrors = document.querySelectorAll(".ip-error");
    const mpuCheckbox = document.getElementById("mpuCheckbox");
    const mcuCheckbox = document.getElementById("mcuCheckbox");
    const iotCheckboxError = document.getElementById("iotCheckboxError");
    const tlsCheckbox = document.getElementById("tlsCheckbox");

    // Create success message element
    const successMessage = document.createElement("p");
    successMessage.id = "success-message";
    successMessage.style.display = "none";
    successMessage.style.color = "green";
    successMessage.style.fontWeight = "bold";
    successMessage.textContent = "Certificate generated successfully!";
    certForm.parentNode.insertBefore(successMessage, certActions);


    // Reset checkboxes and inputs on page load
    function resetCheckboxes() {
        fqdnCheckboxes.forEach(checkbox => checkbox.checked = false);
        ipCheckboxes.forEach(checkbox => checkbox.checked = false);
        fqdnErrors.forEach(error => error.textContent = "");
        ipErrors.forEach(error => error.textContent = "");
        fqdnInputs.forEach(input => {
            input.style.display = "none";
            input.value = "";
        });
        ipInputs.forEach(input => {
            input.style.display = "none";
            input.value = "";
        });
        mpuCheckbox.checked = false;
        mcuCheckbox.checked = false;
        tlsCheckbox.checked = false;
        iotCheckboxError.textContent = "";
    }
    resetCheckboxes();
    function updateInputVisibility(event) {
        const target = event.target;
        if (target.classList.contains("fqdn-checkbox")) {

            fqdnCheckboxes.forEach((checkbox, index) => {
                if (checkbox.checked) {
                    ipCheckboxes[index].checked = false; // Uncheck IP if FQDN is checked
                    fqdnInputs[index].style.display = "inline-block";
                    ipInputs[index].style.display = "none";
                    ipInputs[index].value = "";
                    ipErrors[index].textContent = "";
                    fqdnInputs[index].required = true;
                } else {
                    fqdnInputs[index].style.display = "none";
                    fqdnInputs[index].value = "";
                    fqdnInputs[index].required = false;
                    fqdnErrors[index].textContent = "";
                }
            });
        }
        if (target.classList.contains("ip-checkbox")) {

            ipCheckboxes.forEach((checkbox, index) => {
                if (checkbox.checked) {
                    fqdnCheckboxes[index].checked = false; // Uncheck FQDN if IP is checked
                    ipInputs[index].style.display = "inline-block";
                    ipInputs[index].required = true;
                    fqdnInputs[index].style.display = "none";
                    fqdnInputs[index].value = "";
                    fqdnErrors[index].textContent = "";

                } else {
                    ipInputs[index].style.display = "none";
                    ipInputs[index].value = "";
                    ipInputs[index].required = false;
                    ipErrors[index].textContent = "";
                }
            });
        }
    }
    // Add event listeners to checkboxes
    mpuCheckbox.addEventListener("change", function () {
        if (this.checked) {
            mcuCheckbox.checked = false; // Uncheck mcuCheckbox if mpuCheckbox is checked
            tlsCheckbox.checked = false; // Uncheck tlsCheckbox if mpuCheckbox is checked
        }
    }
    );
    mcuCheckbox.addEventListener("change", function () {
        if (this.checked) {
            mpuCheckbox.checked = false; // Uncheck mpuCheckbox if mcuCheckbox is checked
            tlsCheckbox.checked = false; // Uncheck tlsCheckbox if mcuCheckbox is checked
        }
    });
    tlsCheckbox.addEventListener("change", function () {
        if (this.checked) {
            mpuCheckbox.checked = false; // Uncheck mpuCheckbox if tlsCheckbox is checked
            mcuCheckbox.checked = false; // Uncheck mcuCheckbox if tlsCheckbox is checked
            iotCheckboxError.textContent = "";
        }
    }   
    );
    fqdnCheckboxes.forEach(checkbox => checkbox.addEventListener("change", updateInputVisibility));
    ipCheckboxes.forEach(checkbox => checkbox.addEventListener("change", updateInputVisibility));

    function validateInput() {
        let isValid = true;
        let cnType = null;
        let commonName = null;
        let device = null;

        const ipPattern = /^(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)$/;
        const fqdnPattern = /^(?!:\/\/)([a-zA-Z0-9-_]{1,63}\.)+[a-zA-Z]{2,6}$/;
        let atLeastOneChecked = false;
        fqdnCheckboxes.forEach((checkbox, index) => {
            if (checkbox.checked) {
                atLeastOneChecked = true;
                const input = fqdnInputs[index];
                const error = fqdnErrors[index];

                // do not validate FQDN for now, just check if it is empty
                if (input.value.trim() === "") {
                    error.textContent = "FQDN cannot be empty.";
                    isValid = false;
                }
                else {
                    fqdnErrors[index].textContent = "";
                    cnType = "fqdn";
                    commonName = input.value.trim();
                }
                // if (!fqdnPattern.test(input.value.trim())) {
                //     error.textContent = "Invalid FQDN format.";
                //     isValid = false;
                // } else {
                //     fqdnErrors[index].textContent = "";
                //     cnType = "fqdn";
                //     commonName = input.value.trim();
                // }
            }
        });

        ipCheckboxes.forEach((checkbox, index) => {
            if (checkbox.checked) {
                atLeastOneChecked = true;
                const input = ipInputs[index];
                const error = ipErrors[index];

                if (!ipPattern.test(input.value.trim())) {
                    ipErrors[index].textContent = "Invalid IP address format.";
                    isValid = false;
                } else {
                    error.textContent = "";
                    cnType = "ip";
                    commonName = input.value.trim();
                }
            }
        });
        if (!atLeastOneChecked) {
            alert("Please select at least one FQDN or IP address.");
            isValid = false;
        }
        if (!mpuCheckbox.checked && !mcuCheckbox.checked && !tlsCheckbox.checked) {
            iotCheckboxError.textContent = "Please select the purpose.";
            isValid = false;
        }
        else {
            iotCheckboxError.textContent = "";
            if (mpuCheckbox.checked) {
                device = "mpu";
            }
            else if (mcuCheckbox.checked) {
                device = "mcu";
            }
            else if (tlsCheckbox.checked) {
                device = "tls";
            }
        }

        return { isValid, cnType, commonName, device };
    }
    form = document.getElementById("certForm");
    form.addEventListener("submit", function (event) {
        event.preventDefault();
        // Simulate certificate generation
        let algorithm = document.getElementById('key_algorithm').value;
        let commonName = null;
        let cnType = null;
        
        const validation = validateInput();
        if (!validation.isValid) return;
        form.style.display = "none";
        commonName = validation.commonName;
        cnType = validation.cnType;
        device = validation.device;
        const data = {
            common_name: commonName,
            algorithm: algorithm,
            purpose: purpose,
            cn_type: cnType,
            device: device
        };
        console.log(data);
        fetch(`/generate_certificate/${chain}/${purpose}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        }).then(response => response.json())
            .then(data => {
                certActions.style.display = "flex";
                if (data.certificate) {
                    certContent.style.display = "block";
                    certText.textContent = data.certificate;
                }
                successMessage.style.display = "block";
                certActions.style.display = "flex";
                latestCertInfo = {
                    ca: data.ca,
                    certificate_id: data.certificate_id
                };
                certificateDownloaded = false; // Reset the flag when a new certificate is generated
                console.log(certificateDownloaded)
                downloadBtn.addEventListener("click", function () {
                    if (certificateDownloaded) {
                        console.log("Certificate already downloaded. Cannot download again.");
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
                        console.log("Certificate downloaded successfully");
                        certificateDownloaded = true; // Set the flag to true after successful download
                        })
                        .catch(error => {
                            console.error("Error downloading certificate:", error);
                            alert("Error: Failed to download key. It may have already been deleted.");
                        });
                }); // end event download

            })
            .catch(error => {
                console.error("Error generating the certificate: ", error);
            });
    });
});
