'use strict';
(function () {
  const form = document.getElementById('auth-form');
  const message = document.getElementById('message');
  const mode = form.dataset.mode;
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    message.classList.add('hidden');
    const button = form.querySelector('button');
    button.disabled = true;
    try {
      await api('POST', `/api/auth/${mode}`, { email: form.email.value, password: form.password.value });
      location.href = '/dashboard';
    } catch (err) {
      message.textContent = err.message;
      message.classList.remove('hidden');
    } finally {
      button.disabled = false;
    }
  });
})();
