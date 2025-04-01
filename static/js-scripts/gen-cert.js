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
    document.getElementById("submitButton").addEventListener("click", function (event) {
        event.preventDefault();

        if (purpose === "code-signing") {
            fetch(`/generate_certificate/${purpose}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ algorithm: document.getElementById('key_algorithm').value })
            }).then(response => response.json())
                .then(data => {
                    certActions.style.display = "flex";
                    if (data.certificate) {
                        certContent.style.display = "block";
                        certText.textContent = data.certificate;
                    }
                });
        } else {
            const validation = validateInput();
            if (!validation.isValid) return;

            fetch(`/generate_certificate/${purpose}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    algorithm: document.getElementById('key_algorithm').value,
                    commonName: validation.commonName,
                    cn_type: validation.cnType
                })
            }).then(response => response.json())
                .then(data => {
                    certActions.style.display = "flex";
                    if (data.certificate) {
                        certContent.style.display = "block";
                        certText.textContent = data.certificate;
                    }
                });
        }
    });
});
