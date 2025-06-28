document.addEventListener('DOMContentLoaded', () => {
    const openTutorialBtn = document.getElementById('open-tutorial');
    const tutorialModal = document.getElementById('tutorial-modal');
    const closeTutorialBtn = document.getElementById('close-tutorial');
    const prevStepBtn = document.getElementById('prev-step');
    const nextStepBtn = document.getElementById('next-step');
    const steps = document.querySelectorAll('#tutorial-steps .step');

    let currentStep = 0;

    if (!openTutorialBtn || !tutorialModal || !closeTutorialBtn || !prevStepBtn || !nextStepBtn || !steps.length) {
        return;
    }

    steps[currentStep].classList.remove('hidden');

    openTutorialBtn.addEventListener('click', () => {
        tutorialModal.style.display = 'flex';
        tutorialModal.classList.add('z-50');
        document.body.style.overflow = 'hidden';
    });

    closeTutorialBtn.addEventListener('click', () => {
        tutorialModal.style.display = 'none';
        steps[currentStep].classList.add('hidden');
        currentStep = 0;
        steps[currentStep].classList.remove('hidden');
        updateButtonStates();
        document.body.style.overflow = 'auto';
    });

    prevStepBtn.addEventListener('click', () => {
        if (currentStep > 0) {
            steps[currentStep].classList.add('hidden');
            currentStep--;
            steps[currentStep].classList.remove('hidden');
            updateButtonStates();
        }
    });

    nextStepBtn.addEventListener('click', () => {
        if (currentStep < steps.length - 1) {
            steps[currentStep].classList.add('hidden');
            currentStep++;
            steps[currentStep].classList.remove('hidden');
            updateButtonStates();
        }
    });

    function updateButtonStates() {
        prevStepBtn.disabled = currentStep === 0;
        nextStepBtn.disabled = currentStep === steps.length - 1;
        prevStepBtn.classList.toggle('opacity-50', currentStep === 0);
        nextStepBtn.classList.toggle('opacity-50', currentStep === steps.length - 1);
    }

    updateButtonStates();
});