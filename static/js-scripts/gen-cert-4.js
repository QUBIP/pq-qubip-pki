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

    // Common Name fields
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

    const successMessage = document.createElement("p");
    successMessage.id = "success-message";
    successMessage.style.display = "none";
    successMessage.style.color = "green";
    successMessage.style.fontWeight = "bold";
    successMessage.textContent = "Certificate generated successfully!";
    certForm.parentNode.insertBefore(successMessage, certActions);

    function showLoader() {
        const loader = document.getElementById("loader");
        loader.style.display = "flex";
    }

    function hideLoader() {
        const loader = document.getElementById("loader");
        loader.style.display = "none";
    }

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
                    ipCheckboxes[index].checked = false;
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
                    fqdnCheckboxes[index].checked = false;
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

    mpuCheckbox.addEventListener("change", function () {
        if (this.checked) {
            mcuCheckbox.checked = false;
            tlsCheckbox.checked = false;
        }
    });

    mcuCheckbox.addEventListener("change", function () {
        if (this.checked) {
            mpuCheckbox.checked = false;
            tlsCheckbox.checked = false;
        }
    });

    tlsCheckbox.addEventListener("change", function () {
        if (this.checked) {
            mpuCheckbox.checked = false;
            mcuCheckbox.checked = false;
            iotCheckboxError.textContent = "";
        }
    });

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
                if (input.value.trim() === "") {
                    error.textContent = "FQDN cannot be empty.";
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
        } else {
            iotCheckboxError.textContent = "";
            if (mpuCheckbox.checked) device = "mpu";
            else if (mcuCheckbox.checked) device = "mcu";
            else if (tlsCheckbox.checked) device = "tls";
        }

        return { isValid, cnType, commonName, device };
    }

    const form = document.getElementById("certForm");

    form.addEventListener("submit", function (event) {
        event.preventDefault();

        showLoader();
        const validation = validateInput();
        if (!validation.isValid) return;

        setTimeout(() => {
            form.style.display = "none";
            const algorithm = document.getElementById('key_algorithm').value;
            let commonName = null;
            let cnType = null;


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
            //console.log("Data to be sent:", data);
            fetch(`/generate_certificate/${purpose}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            }).then(response => response.json())
                .then(data => {
                    hideLoader();
                    certActions.style.display = "flex";
                    if (data.certificate) {
                        certContent.style.display = "block";
                        certText.textContent = data.certificate;
                    }
                    successMessage.style.display = "block";
                    certActions.style.display = "flex";
                    latestCertInfo = {
                        ca: data.ca,
                        certificate_id: data.certificate_id,
                        pki: data.pki
                    };
                    certificateDownloaded = false;
                })
                .catch(error => {
                    hideLoader();
                    console.error("Error generating the certificate: ", error);
                });

        }, 3);

    });

    downloadBtn.addEventListener("click", function () {
        if (certificateDownloaded) {
            alert("The private key has been deleted for security reasons. Please generate another certificate if you need it.");
            return;
        }

        const userConfirmed = confirm("Warning: This certificate and private key can only be downloaded ONCE. After that, the private key will be deleted from the server. Do you want to proceed?");
        if (!userConfirmed) return;

        if (!latestCertInfo) {
            alert("No certificate available to download.");
            return;
        }
        //console.log(latestCertInfo)

        fetch(`/download_certificate/${latestCertInfo.pki}/${latestCertInfo.ca}/${latestCertInfo.certificate_id}`, { method: 'GET' })
            .then(response => {
                if (!response.ok) throw new Error('Failed to download certificate');
                return response.blob();
            })
            .then(blob => {
                const link = document.createElement('a');
                link.href = URL.createObjectURL(blob);
                link.download = `${latestCertInfo.certificate_id}.zip`;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                certificateDownloaded = true;
            })
            .catch(error => {
                console.error("Error downloading certificate:", error);
            });
    });
});
