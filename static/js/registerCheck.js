let userName = document.querySelector('#user-reg');

userName.addEventListener('keyup', function () {
  let signUpButton = document.querySelector('#submit-reg');
  setTimeout(async function () {
    let msgBoxUser = document.querySelector('#user-error');
    let value = userName.value;
    let response = await fetch('/check', {
      method: 'POST',
      body: JSON.stringify(value),
    });
    if (response.status == 208) {
      msgBoxUser.innerHTML = `<p class="error-p">Username already registered</p>`;
      signUpButton.disabled = true;
    } else {
      msgBoxUser.innerHTML = '';
      signUpButton.disabled = false;
    }
  }, 400);
});

let passInput = document.querySelector('#pass-input');
let passVerification = document.querySelector('#pass-repeat');
let submitButton = document.querySelector('#submit-reg');

let msgBoxPass = document.querySelector('#pass-error');
let msgBoxVerify = document.querySelector('#pass-verify');

passInput.addEventListener('keyup', function () {
  if (passInput.value.length < 8) {
    msgBoxPass.innerHTML = `<p class="error-p">Password must be at least 8 characters long</p>`;
  } else {
    msgBoxPass.innerHTML = '';
  }
});

passVerification.addEventListener('keyup', function () {
  setInterval(() => {
    if (passVerification.value != passInput.value) {
      msgBoxVerify.innerHTML = `<p class="error-p">Passwords do not match</p>`;
      submitButton.disabled = true;
    } else {
      msgBoxVerify.innerHTML = '';
      submitButton.disabled = false;
    }
  }, 1000);
});
