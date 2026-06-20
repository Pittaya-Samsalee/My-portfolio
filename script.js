document.addEventListener('DOMContentLoaded', () => {

    // 1. Counter Logic
    const counters = document.querySelectorAll('.count-num');

    counters.forEach(counter => {
        const target = +counter.getAttribute('data-target');
        if (!target || isNaN(target)) return;

        const duration = 2000;
        const stepTime = 20;
        const steps = duration / stepTime;
        const increment = target / steps;

        let current = 0;
        let stepCount = 0;

        const timer = setInterval(() => {
            stepCount++;
            current += increment;

            if (stepCount >= steps) {
                clearInterval(timer);
                counter.innerText = target;
            } else {
                counter.innerText = Math.floor(current);
            }
        }, stepTime);
    });


    // 2. Form Validation Logic
    const contactForm = document.getElementById('contactForm');

    if (contactForm) {
        contactForm.addEventListener('submit', function (event) {
            event.preventDefault();

            const nameInput = document.getElementById('nameInput');
            const emailInput = document.getElementById('emailInput');
            const messageInput = document.getElementById('messageInput');

            const nameValue = nameInput ? nameInput.value.trim() : '';
            const emailValue = emailInput ? emailInput.value.trim() : '';
            const messageValue = messageInput ? messageInput.value.trim() : '';

            const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

            if (nameValue === "" || emailValue === "" || messageValue === "") {
                alert("Please enter your name.\nPlease enter your email address.\nPlease write your message.");
                return;
            }

            if (!emailPattern.test(emailValue)) {
                alert("Please enter a valid email address.");
                return;
            }

            localStorage.setItem('lastMessage', nameValue);
            alert("Message sent successfully!");
            contactForm.reset();
        });
    }


    // 3. Hamburger Menu
    const hamburger = document.getElementById('hamburger');
    const navLinks = document.querySelector('.nav-links');

    if (hamburger && navLinks) {
        hamburger.addEventListener('click', () => {
            navLinks.classList.toggle('active');
        });
    }


    // 4. Section Reveal Animation
    const revealSections = document.querySelectorAll('.skills-section, .goals-section');

    const revealObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
            }
        });
    }, {
        threshold: 0.15
    });

    revealSections.forEach(section => {
        revealObserver.observe(section);
    });

});