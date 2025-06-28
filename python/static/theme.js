document.querySelector('input[type="submit"]').disabled = true;
document.addEventListener('DOMContentLoaded', () => {
    const body = document.body;
    const solutionModal = document.getElementById('solution-modal');
    const solutionContent = solutionModal ? solutionModal.querySelector('.modal-content') : null;

    // Enforce dark mode
    body.classList.remove('light');
    body.classList.add('dark');

    // Ensure solution modal is styled for dark mode
    if (solutionModal && solutionContent) {
        solutionContent.classList.remove('bg-white');
        solutionContent.classList.add('bg-gray-800');
        const textElements = solutionContent.querySelectorAll('p, h3');
        textElements.forEach(el => {
            if (el.tagName === 'H3') {
                el.classList.remove('text-gray-800');
                el.classList.add('text-gray-200');
            } else {
                el.classList.remove('text-gray-600');
                el.classList.add('text-gray-400');
            }
        });
    }
});