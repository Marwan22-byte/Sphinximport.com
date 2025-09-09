// Dropdown menu logic
document.querySelectorAll('.dropdown').forEach(item => {
    item.addEventListener('mouseenter', () => {
        item.querySelector('.dropdown-menu').style.display = 'block';
    });
    item.addEventListener('mouseleave', () => {
        item.querySelector('.dropdown-menu').style.display = 'none';
    });
});

// Contact Form Submission (AJAX)
document.addEventListener('DOMContentLoaded', function () {
    const form = document.getElementById('contactForm');
    if(form){
        form.addEventListener('submit', async function(e){
            e.preventDefault();
            const data = Object.fromEntries(new FormData(form));
            const msgDiv = document.getElementById('formMsg');
            msgDiv.textContent = "Sending...";
            msgDiv.style.color = "#23233c";
            try {
                const resp = await fetch('/send-message', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                const resData = await resp.json();
                msgDiv.textContent = resData.msg;
                msgDiv.style.color = resData.success ? 'green' : 'red';
                if(resData.success) form.reset();
            } catch (err) {
                msgDiv.textContent = "Something went wrong. Please try again.";
                msgDiv.style.color = 'red';
            }
        });
    }
});