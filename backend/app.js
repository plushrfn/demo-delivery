const connectForm = document.getElementById('connect-form');
const selectionError = document.getElementById('selection-error');

if (connectForm && selectionError) {
  connectForm.addEventListener('submit', (event) => {
    if (!connectForm.querySelector('input[name="scope"]:checked')) {
      event.preventDefault();
      selectionError.textContent = 'Выберите хотя бы одно поле для запроса.';
      selectionError.classList.remove('hidden');
    }
  });
  connectForm.addEventListener('change', () => {
    selectionError.classList.add('hidden');
    selectionError.textContent = '';
  });
}
