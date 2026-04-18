// Navigate to security check
function navigateToHome() {
    window.location.href = "/home";
}

// Smooth scroll to "How It Works" section
function scrollToHowItWorks() {
    const howItWorksSection = document.querySelector('.how-it-works');
    if (howItWorksSection) {
        howItWorksSection.scrollIntoView({ 
            behavior: 'smooth',
            block: 'start'
        });
    }
}

// Attach event listener for "Learn More" button (avoids inline onclick handler)
document.addEventListener('DOMContentLoaded', function () {
    const learnMoreBtn = document.getElementById('learn-more-btn');
    if (learnMoreBtn) {
        learnMoreBtn.addEventListener('click', scrollToHowItWorks);
    }
});

