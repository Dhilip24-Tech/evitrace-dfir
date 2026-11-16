(() => {
  const button = document.querySelector('.copy');
  const status = document.querySelector('.copy__status');
  if (!button || !status) return;
  const label = button.textContent;
  let timer;

  const legacyCopy = () => {
    const area = document.createElement('textarea');
    area.value = button.dataset.copy || '';
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.top = '0';
    area.style.opacity = '0';
    document.body.append(area);
    area.select();
    let copied = false;
    try {
      copied = document.execCommand('copy');
    } catch {
      copied = false;
    }
    area.remove();
    return copied;
  };

  button.addEventListener('click', async () => {
    clearTimeout(timer);
    let copied = false;
    try {
      await navigator.clipboard.writeText(button.dataset.copy);
      copied = true;
    } catch {
      copied = legacyCopy();
    }
    button.textContent = copied ? 'Copied' : 'Copy failed';
    status.textContent = copied ? 'Command copied.' : 'Select the command and copy it.';
    timer = setTimeout(() => {
      button.textContent = label;
      status.textContent = '';
    }, 3000);
  });
})();
