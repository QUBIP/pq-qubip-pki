document.addEventListener("DOMContentLoaded", function () {
    const certForm = document.getElementById("certForm");
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
    fqdnCheckboxes.forEach(checkbox => checkbox.addEventListener("change", updateInputVisibility));
    ipCheckboxes.forEach(checkbox => checkbox.addEventListener("change", updateInputVisibility));

    function validateInput() {
        let isValid = true;
        let cnType = null;
        let commonName = null;

        const ipPattern = /^(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)$/;
        const fqdnPattern = /^(?!:\/\/)([a-zA-Z0-9-_]{1,63}\.)+[a-zA-Z]{2,6}$/;

        fqdnCheckboxes.forEach((checkbox, index) => {
            if (checkbox.checked) {
                const input = fqdnInputs[index];
                const error = fqdnErrors[index];
                if (!fqdnPattern.test(input.value.trim())) {
                    error.textContent = "Invalid FQDN format.";
                    isValid = false;
                } else {
                    fqdnErrors[index].textContent = "";
                    cnType = "fqdn";
                    commonName = input.value.trim();
                }
            }
        });

        ipCheckboxes.forEach((checkbox, index) => {
            if (checkbox.checked) {
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

        return { isValid, cnType, commonName };
    }
    form = document.getElementById("certForm");
    form.addEventListener("submit", function (event) {
        event.preventDefault();
        // Simulate certificate generation
        form.style.display = "none";
        let algorithm = document.getElementById('key_algorithm').value;
        let commonName = null;
        let cnType = null;
        if (purpose === "code-signing") {
            commonName = "";
            cnType = "";
        } else {
            // tls-server or tls-client

            const validation = validateInput();
            if (!validation.isValid) return;
            // console.log('Form submitted');
            commonName = validation.commonName;
            cnType = validation.cnType;
        }
        const data = {
            common_name: commonName,
            algorithm: algorithm,
            purpose: purpose,
            cn_type: cnType
        };
        console.log(data);
        fetch(`/generate_certificate/${purpose}`, {
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
                            alert("Error: Failed to download key. It may have already been deleted.");
                        });
                }); // end event download

            })
            .catch(error => {
                console.error("Error generating the certificate: ", error);
            });
    });
});
