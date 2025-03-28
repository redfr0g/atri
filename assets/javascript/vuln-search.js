const searchInput = document.getElementById("vuln-search-box");
const detailsElements = document.querySelectorAll("details");
searchInput.addEventListener("input", () => {
  const searchTerm = searchInput.value.toLowerCase();
  let regex;
  try {
    regex = new RegExp(searchTerm, "i");
  } catch (e) {
    regex = /^(?!.*)/;
  }
  detailsElements.forEach((detail) => {
    const summary = detail.querySelector("summary").textContent.toLowerCase();
    const content = [
      detail.querySelectorAll("p")[0].textContent.toLowerCase(),
      detail.querySelectorAll("p")[1].textContent.toLowerCase(),
      detail.querySelectorAll("p")[2].textContent.toLowerCase(),
    ];
    if (regex.test(summary) || regex.test(content)) {
      detail.style.display = "";
    } else {
      detail.style.display = "none";
    }
  });
});
