/* global webauthn A11yDialog saveAs Toastify */
(() => {
  const result = new A11yDialog(document.querySelector("#result-dialog"));
  result.on("show", function (dialogEl) {
    dialogEl.classList.remove("hide");
  });
  function toast(text) {
    Toastify({
      text,
      duration: 3000,
      gravity: "bottom", // `top` or `bottom`
      position: "center", // `left`, `center` or `right`
      stopOnFocus: true, // Prevents dismissing of toast on hover
    }).showToast();
  }
  function resultDialog(title, identicon, by, on, hash) {
    document.querySelector("#result-dialog-title").textContent = title;
    document.querySelector("#result-identicon").src = identicon;
    document.querySelector("#result-key").textContent = by;
    document.querySelector("#result-origin").textContent = on;
    document.querySelector("#result-hash").textContent = hash;
    result.show();
  }
  document.querySelector("#load").addEventListener("submit", async (e) => {
    try {
      e.preventDefault();
      const signedFile = document.querySelector("#file").files[0];
      const { sigBlob, b64FileHash, identicon, b64Pky } = await webauthn.sign(
        signedFile
      );
      saveAs(sigBlob, signedFile.name + ".wsig");
      resultDialog(
        "Signed File",
        identicon,
        b64Pky,
        location.origin,
        b64FileHash
      );
    } catch (e) {
      if (e instanceof webauthn.UserFacingError) {
        toast(e.message);
      } else {
        console.error(e);
        toast("There was an error signing the file");
      }
    }
  });
  document.querySelector("#verify").addEventListener("submit", async (e) => {
    try {
      e.preventDefault();
      const signedFile = document.querySelector("#vfile").files[0];
      const fileHash = await crypto.subtle.digest(
        "SHA-256",
        await new Response(signedFile).arrayBuffer()
      );
      const signatureFile = await new Response(
        document.querySelector("#vsig").files[0]
      ).arrayBuffer();
      const { b64FileHash, identicon, b64Pky, origin } = await webauthn.verify(
        fileHash,
        signatureFile
      );
      resultDialog(
        "Verified Signature",
        identicon,
        b64Pky,
        origin,
        b64FileHash
      );
    } catch (e) {
      if (e instanceof webauthn.UserFacingError) {
        toast(e.message);
      } else {
        console.error(e);
        toast("There was an error verifying the signature");
      }
    }
  });
  document.querySelector("#create").addEventListener("click", async () => {
    try {
      saveAs(await webauthn.newIdentity(), "key.wsid");
    } catch (e) {
      if (e instanceof webauthn.UserFacingError) {
        toast(e.message);
      } else {
        console.error(e);
        toast("Error creating a new Identity");
      }
    }
  });
  for (let icon of document.querySelectorAll(".file .fileicon")) {
    const label = icon.parentElement;
    const input = label.querySelector("input");
    const name = label.querySelector(".filename");
    const clear = label.querySelector(".clearfile");
    const thumb = icon.querySelector(".thumb");
    clear.addEventListener("click", (e) => {
      e.preventDefault();
      input.value = null;
      input.dispatchEvent(new Event("change"));
    });
    input.addEventListener("change", () => {
      const file = input.files[0];
      if (file) {
        if (thumb) {
          (async () => {
            try {
              thumb.style.display = "none";
              const keyData = await webauthn.decodeIdentity(
                await new Response(
                  document.querySelector("#identity").files[0]
                ).arrayBuffer()
              );
              thumb.style.setProperty(
                "--identicon",
                "url(" + keyData.identicon + ")"
              );
              thumb.style.display = "";
            } catch (e) {
              if (e instanceof webauthn.UserFacingError) {
                toast(e.message);
              } else {
                console.error(e);
                toast("That Identity file is invalid");
              }
              input.value = null;
              input.dispatchEvent(new Event("change"));
            }
          })();
        }
        name.textContent = file.name;
        label.classList.remove("empty");
      } else {
        if (thumb) thumb.style.display = "none";
        label.classList.add("empty");
      }
    });
    input.dispatchEvent(new Event("change"));
  }
})();
