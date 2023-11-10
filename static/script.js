const loadingBar = document.getElementById("loadingBar");
const progressBar = document.getElementById("progress");
const progressText = document.getElementById("progressText");
const scanStatus = document.getElementById("scanStatus");
const startScanButton = document.getElementById("startScan");
const resultsSection = document.getElementById("results");
const resultsText = document.getElementById("resultsText");

// Declare the url_to_check variable
let url_to_check;

// Define determineBackgroundColor function
function determineBackgroundColor(vulnerabilities) {
  // Check if vulnerabilities is an array and has at least one element
  if (Array.isArray(vulnerabilities) && vulnerabilities.length > 0) {
    // Implement logic to determine severity and return the corresponding color
    // Example: check if there is a critical vulnerability
    if (vulnerabilities.includes("Critical Vulnerability")) {
      return "red";
    }
  }

  // Default color if no vulnerabilities or not an array
  return "green";
}

startScanButton.addEventListener("click", function () {
  // Reset progress
  progress = 0;
  progressBar.style.width = "0%";
  progressText.innerText = "0%";

  // Obtain the value from the input field
  url_to_check = document.getElementById("url").value;

  // Make an AJAX request to initiate the scan
  fetch("/start_scan", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ url: url_to_check }),
  })
    .then((response) => response.json())
    .then((data) => {
      // Handle the response from the server, update progress, etc.
      console.log(data);

      // Simulate the scan progress for demonstration purposes
      const interval = setInterval(() => {
        progress += 10;
        progressBar.style.width = `${progress}%`;
        progressText.innerText = `${progress}%`;

        if (progress >= 100) {
          clearInterval(interval);
          scanStatus.innerText = `Scan completed at ${new Date().toLocaleString()}. Redirecting to results...`;

          // Display results section
          resultsText.innerText = `Results for ${data.url}`;
          resultsSection.classList.remove("hidden");

          // Display vulnerabilities
          displayVulnerabilities(data.vulnerabilities);

          // Change background color based on severity
          resultsSection.style.backgroundColor = determineBackgroundColor(data.vulnerabilities);
        }
      }, 500);
    })
    .catch((error) => {
      console.error("Error:", error);
      // Handle the error appropriately (e.g., display an error message)
    });
});

function displayVulnerabilities(vulnerabilities) {
  const vulnerabilitiesList = document.createElement("ul");

  if (Array.isArray(vulnerabilities) && vulnerabilities.length > 0) {
    vulnerabilities.forEach((vulnerability) => {
      const listItem = document.createElement("li");
      listItem.innerText = vulnerability;
      vulnerabilitiesList.appendChild(listItem);
    });
  } else {
    // Display a message if no vulnerabilities are found
    const noVulnerabilitiesMessage = document.createElement("p");
    noVulnerabilitiesMessage.innerText = "No vulnerabilities found.";
    vulnerabilitiesList.appendChild(noVulnerabilitiesMessage);
  }

  resultsSection.appendChild(vulnerabilitiesList);
}
