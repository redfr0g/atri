function createChart(issue_array) {
    const vulnerabilitiesBySeverity = {
        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
        data: issue_array
    };

    const ctx = document.getElementById('severityChart').getContext('2d');
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: vulnerabilitiesBySeverity.labels,
            datasets: [{
                data: vulnerabilitiesBySeverity.data,
                backgroundColor: ["#30130a","#d93526","#ff9500","#4eb31b","#018cd4"],
                hoverBackgroundColor: ["#52241b", "#f04938", "#ffae33", "#65c635", "#31a5e3"]
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
}