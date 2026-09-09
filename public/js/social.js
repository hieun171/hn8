function socialFocusComment(postId) {
  const form = document.getElementById("social-comment-" + postId);

  if (!form) return;

  const input = form.querySelector("input[name='comment']");

  if (!input) return;

  input.focus();

  input.scrollIntoView({
    behavior: "smooth",
    block: "center",
  });
}

function socialShowReply(commentId, parentReplyId = null) {
  let form;

  if (!parentReplyId) {
    form = document.getElementById("social-reply-" + commentId);
  } else {
    form = document.getElementById("social-reply-to-" + parentReplyId);
  }

  if (!form) {
    console.log("FORM NOT FOUND", {
      commentId,
      parentReplyId,
    });

    return;
  }

  if (form.style.display === "none" || !form.style.display) {
    form.style.display = "flex";

    const input = form.querySelector("input[name='reply']");

    if (input) {
      input.focus();

      input.scrollIntoView({
        behavior: "smooth",
        block: "center",
      });
    }
  } else {
    form.style.display = "none";
  }
}

function socialEditPost(postId) {
  const content = prompt("Edit your post:");

  if (content === null) {
    return;
  }

  const trimmed = content.trim();

  if (!trimmed) {
    return;
  }

  if (trimmed.length > 5000) {
    alert("Your post is too long. Please keep it under 5000 characters.");
    return;
  }

  const form = document.createElement("form");

  form.method = "POST";
  form.action = "/social/post/edit";

  const id = document.createElement("input");

  id.type = "hidden";
  id.name = "id";
  id.value = postId;

  const text = document.createElement("input");

  text.type = "hidden";
  text.name = "content";
  text.value = trimmed;

  form.appendChild(id);
  form.appendChild(text);

  document.body.appendChild(form);

  form.submit();
}

document.addEventListener("click", async (event) => {
  const button = event.target.closest(".social-share-button");

  if (!button) {
    return;
  }

  const postId = button.dataset.postId;

  if (!postId) {
    return;
  }

  const originalHTML = button.innerHTML;

  try {
    button.disabled = true;

    button.innerHTML = "⏳ <span>Sharing...</span>";

    const response = await fetch("/social/post/share", {
      method: "POST",

      headers: {
        "Content-Type": "application/json",
      },

      body: JSON.stringify({
        postId: postId,
      }),
    });

    const data = await response.json();

    if (!response.ok || !data.success) {
      throw new Error(data.error || "Unable to share post.");
    }

    if (navigator.share) {
      await navigator.share({
        title: "Social Post",
        text: "Check out this post",
        url: data.url,
      });
    } else if (navigator.clipboard) {
      await navigator.clipboard.writeText(data.url);

      button.innerHTML = "✓ <span>Link copied</span>";

      setTimeout(() => {
        button.innerHTML = originalHTML;
      }, 2000);

      return;
    }

    button.innerHTML = "✓ <span>Shared</span>";

    setTimeout(() => {
      button.innerHTML = originalHTML;
    }, 2000);
  } catch (err) {
    if (err.name === "AbortError") {
      button.innerHTML = originalHTML;
      return;
    }

    console.error("Share error:", err);

    button.innerHTML = "⚠️ <span>Share failed</span>";

    setTimeout(() => {
      button.innerHTML = originalHTML;
    }, 2000);
  } finally {
    button.disabled = false;
  }
});
//
// ============================================================
// SOCIAL POST CREATE
// ============================================================

const socialPostCreateComposer = document.getElementById(
  "socialPostCreateComposer",
);

const socialPostCreateContent = document.getElementById(
  "socialPostCreateContent",
);

const socialPostFilesInput = document.getElementById("socialPostFiles");

const socialPostFilesPreview = document.getElementById(
  "socialPostFilesPreview",
);

// ============================================================
// FORM SOCIAL POST CREATE
// ============================================================

const socialPostCreateForm = document.getElementById("socialCreatePostForm");

// ============================================================
// CLIENT-ONLY VISIBILITY SELECTOR
// ============================================================

const socialVisibilityClientOnly = document.getElementById(
  "socialVisibilityClientOnly",
);

const socialClientSelector = document.getElementById("socialClientSelector");

const socialTargetUserId = document.getElementById("socialTargetUserId");

function socialUpdateClientSelector() {
  if (!socialVisibilityClientOnly || !socialClientSelector) {
    return;
  }

  if (socialVisibilityClientOnly.checked) {
    socialClientSelector.style.display = "block";
  } else {
    socialClientSelector.style.display = "none";

    if (socialTargetUserId) {
      socialTargetUserId.value = "";
    }
  }
}

// When visibility changes
document.querySelectorAll('input[name="visibility"]').forEach((radio) => {
  radio.addEventListener("change", socialUpdateClientSelector);
});

// Initial state
socialUpdateClientSelector();

// ============================================================
// POST BUTTON
// ============================================================

const socialPostCreateButton = socialPostCreateForm?.querySelector(
  'button[type="submit"], input[type="submit"]',
);

//
let socialPostAttachments = [];

let socialPostIsSubmitting = false;

const SOCIAL_MAX_FILES = 10;

const SOCIAL_MAX_FILE_SIZE = 100 * 1024 * 1024;

const SOCIAL_MAX_CONTENT_LENGTH = 5000;

const SOCIAL_ALLOWED_TYPES = [
  "image/jpeg",
  "image/png",
  "image/webp",
  "image/gif",
  "video/mp4",
  "video/webm",
  "audio/mpeg",
  "audio/mp4",
  "audio/wav",
  "audio/ogg",
  "audio/webm",
  "application/pdf",
  "text/csv",
  "application/csv",
  "application/vnd.ms-excel",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
];

function socialAddPostAttachment(file) {
  if (!file) {
    return false;
  }

  if (socialPostAttachments.length >= SOCIAL_MAX_FILES) {
    alert(`You can upload a maximum of ${SOCIAL_MAX_FILES} files.`);

    return false;
  }

  if (file.size > SOCIAL_MAX_FILE_SIZE) {
    alert(`${file.name} is too large. Maximum file size is 100 MB.`);

    return false;
  }

  if (!SOCIAL_ALLOWED_TYPES.includes(file.type)) {
    alert(
      "Only JPG, PNG, WebP, GIF, MP4, WebM, CSV, Excel, Word, and PDF files are allowed.",
    );

    return false;
  }

  if (file.type.startsWith("video/")) {
    const existingVideo = socialPostAttachments.some((attachment) =>
      attachment.file.type.startsWith("video/"),
    );

    if (existingVideo) {
      alert("You can upload only 1 video per post.");
      return false;
    }
  }

  console.log("ADDING ATTACHMENT:", {
    name: file.name,
    type: file.type,
    size: file.size,
  });

  socialPostAttachments.push({
    file: file,
    mediaText: "",
    objectUrl: null,
  });

  socialRenderPostAttachments();

  return true;
}

if (socialPostFilesInput) {
  socialPostFilesInput.addEventListener("change", () => {
    const files = Array.from(socialPostFilesInput.files || []);

    console.log("FILES SELECTED:", files);

    for (const file of files) {
      if (socialPostAttachments.length >= SOCIAL_MAX_FILES) {
        alert(`You can upload a maximum of ${SOCIAL_MAX_FILES} files.`);
        break;
      }

      socialAddPostAttachment(file);
    }

    socialPostFilesInput.value = "";
  });
}

if (socialPostCreateComposer) {
  socialPostCreateComposer.addEventListener("paste", (event) => {
    const clipboardItems = event.clipboardData?.items;

    if (!clipboardItems) {
      return;
    }

    let imageFound = false;

    for (const item of clipboardItems) {
      if (!item.type || !item.type.startsWith("image/")) {
        continue;
      }

      const file = item.getAsFile();

      if (!file) {
        continue;
      }

      imageFound = true;

      const extension =
        file.type === "image/jpeg"
          ? "jpg"
          : file.type === "image/webp"
            ? "webp"
            : file.type === "image/gif"
              ? "gif"
              : "png";

      const pastedFile = new File(
        [file],
        `pasted-image-${Date.now()}.${extension}`,
        {
          type: file.type,
        },
      );

      console.log("PASTED IMAGE:", {
        name: pastedFile.name,
        type: pastedFile.type,
        size: pastedFile.size,
      });

      socialAddPostAttachment(pastedFile);

      // Prevent image from being inserted
      // into contenteditable.
      event.preventDefault();

      break;
    }

    if (imageFound) {
      console.log("PASTE IMAGE CAPTURED");
    }
  });
}

function socialRenderPostAttachments() {
  if (!socialPostFilesPreview) {
    return;
  }

  socialPostFilesPreview.innerHTML = "";

  socialPostAttachments.forEach((attachment, index) => {
    const wrapper = document.createElement("div");

    wrapper.className = "social-post-attachment";

    wrapper.dataset.index = index;

    if (attachment.file.type.startsWith("image/")) {
      const image = document.createElement("img");

      if (!attachment.objectUrl) {
        attachment.objectUrl = URL.createObjectURL(attachment.file);
      }

      image.src = attachment.objectUrl;

      image.alt = attachment.file.name;

      image.className = "social-post-create-pasted-image";

      wrapper.appendChild(image);
    } else if (attachment.file.type.startsWith("video/")) {
      if (!attachment.objectUrl) {
        attachment.objectUrl = URL.createObjectURL(attachment.file);
      }

      const video = document.createElement("video");

      video.src = attachment.objectUrl;

      video.className = "social-post-create-video";

      video.controls = true;

      video.preload = "metadata";

      video.playsInline = true;

      video.muted = true;

      wrapper.appendChild(video);
    } else if (attachment.file.type === "application/pdf") {
      const pdf = document.createElement("div");

      pdf.className = "social-post-pdf-preview";

      pdf.textContent = `📄 ${attachment.file.name}`;

      wrapper.appendChild(pdf);
    }

    const fileName = document.createElement("div");

    fileName.className = "social-post-attachment-name";

    fileName.textContent = attachment.file.name;

    wrapper.appendChild(fileName);

    const fileSize = document.createElement("div");

    fileSize.className = "social-post-attachment-size";

    fileSize.textContent = socialFormatFileSize(attachment.file.size);

    wrapper.appendChild(fileSize);

    const mediaText = document.createElement("textarea");

    mediaText.className = "social-post-media-text";

    mediaText.name = "media_text";

    mediaText.placeholder = "Add text for this image or file...";

    mediaText.value = attachment.mediaText;

    mediaText.maxLength = 5000;

    mediaText.addEventListener("input", () => {
      if (socialPostAttachments[index]) {
        socialPostAttachments[index].mediaText = mediaText.value;
      }
    });

    wrapper.appendChild(mediaText);

    const removeButton = document.createElement("button");

    removeButton.type = "button";

    removeButton.className = "social-post-remove-file";

    removeButton.textContent = "Remove";

    removeButton.addEventListener("click", () => {
      const attachment = socialPostAttachments[index];

      if (attachment?.objectUrl) {
        URL.revokeObjectURL(attachment.objectUrl);
      }

      socialPostAttachments.splice(index, 1);

      socialRenderPostAttachments();
    });

    wrapper.appendChild(removeButton);

    socialPostFilesPreview.appendChild(wrapper);
  });
}

function socialFormatFileSize(bytes) {
  if (!bytes) {
    return "0 B";
  }

  const units = ["B", "KB", "MB", "GB"];

  let size = bytes;

  let unitIndex = 0;

  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex++;
  }

  return `${size.toFixed(unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function socialSetPostButtonState(isPosting) {
  if (!socialPostCreateButton) {
    return;
  }

  if (isPosting) {
    socialPostCreateButton.disabled = true;

    if (socialPostCreateButton.tagName === "INPUT") {
      socialPostCreateButton.value = "⏳ Posting...";
    } else {
      socialPostCreateButton.innerHTML = "⏳ Posting...";
    }

    socialPostCreateButton.setAttribute("aria-busy", "true");
  } else {
    socialPostCreateButton.disabled = false;

    if (socialPostCreateButton.tagName === "INPUT") {
      socialPostCreateButton.value = "Post";
    } else {
      socialPostCreateButton.innerHTML = "Post";
    }

    socialPostCreateButton.removeAttribute("aria-busy");
  }
}

if (!socialPostCreateForm) {
  console.error("SOCIAL POST FORM NOT FOUND: #socialCreatePostForm");
} else {
  console.log("SOCIAL POST FORM FOUND:", socialPostCreateForm);

  socialPostCreateForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    if (socialPostIsSubmitting) {
      console.log("POST ALREADY SUBMITTING");

      return;
    }

    socialPostIsSubmitting = true;

    socialSetPostButtonState(true);

    console.log("================================");

    console.log("POST BUTTON CLICKED");

    console.log("ATTACHMENTS:", socialPostAttachments);

    console.log("================================");

    try {
      const content = socialPostCreateComposer?.innerText.trim() || "";

      if (socialPostCreateContent) {
        socialPostCreateContent.value = content;
      }

      if (!content && socialPostAttachments.length === 0) {
        throw new Error("Post cannot be empty.");
      }

      if (content.length > SOCIAL_MAX_CONTENT_LENGTH) {
        throw new Error(
          "Your post is too long. Please keep it under 5000 characters.",
        );
      }

      for (const attachment of socialPostAttachments) {
        if (attachment.file.size > SOCIAL_MAX_FILE_SIZE) {
          throw new Error(
            `${attachment.file.name} is too large. Maximum file size is 100 MB.`,
          );
        }

        if (!SOCIAL_ALLOWED_TYPES.includes(attachment.file.type)) {
          throw new Error(`File type not allowed: ${attachment.file.name}`);
        }
      }

      const formData = new FormData();

      formData.append("content", content);
      //
      const visibility = socialPostCreateForm.querySelector(
        'input[name="visibility"]:checked',
      );

      const selectedVisibility = visibility?.value || "loggedin users";

      formData.append("visibility", selectedVisibility);

      if (selectedVisibility === "client_only") {
        const targetClient = document.getElementById("socialTargetUserId");

        const targetUserId = targetClient?.value || "";

        if (!targetUserId) {
          throw new Error("Please select a client.");
        }

        formData.append("target_user_id", targetUserId);
      }
      //
      socialPostAttachments.forEach((attachment, index) => {
        console.log("ADDING FILE TO FORM DATA:", {
          index,
          name: attachment.file.name,
          type: attachment.file.type,
          size: attachment.file.size,
        });

        formData.append("files", attachment.file, attachment.file.name);

        formData.append("media_text", attachment.mediaText || "");
      });

      console.log("FORM DATA CONTENT:", content);

      console.log("FORM DATA FILE COUNT:", socialPostAttachments.length);

      for (const [key, value] of formData.entries()) {
        if (value instanceof File) {
          console.log("FORM DATA FILE:", {
            key,
            name: value.name,
            type: value.type,
            size: value.size,
          });
        } else {
          console.log("FORM DATA:", key, value);
        }
      }

      const hasVideo = socialPostAttachments.some((attachment) =>
        attachment.file.type.startsWith("video/"),
      );

      if (hasVideo && socialPostCreateButton) {
        const uploadText = "⏳ Uploading video... 0%";

        if (socialPostCreateButton.tagName === "INPUT") {
          socialPostCreateButton.value = uploadText;
        } else {
          socialPostCreateButton.innerHTML = uploadText;
        }
      }

      console.log("SENDING POST TO:", socialPostCreateForm.action);

      const response = await new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();

        xhr.open("POST", socialPostCreateForm.action, true);

        const uploadStartTime = Date.now();

        xhr.upload.addEventListener("progress", (event) => {
          if (!event.lengthComputable || !hasVideo) {
            return;
          }

          const percent = Math.round((event.loaded / event.total) * 100);

          const elapsedSeconds = (Date.now() - uploadStartTime) / 1000;

          const uploadSpeed =
            elapsedSeconds > 0 ? event.loaded / elapsedSeconds : 0;

          const remainingBytes = event.total - event.loaded;

          const remainingSeconds =
            uploadSpeed > 0 ? remainingBytes / uploadSpeed : 0;

          let timeText = "";

          if (remainingSeconds > 60) {
            timeText = ` — ~${Math.ceil(remainingSeconds / 60)} min left`;
          } else if (remainingSeconds > 0) {
            timeText = ` — ~${Math.ceil(remainingSeconds)} sec left`;
          }

          console.log(
            `UPLOAD PROGRESS: ${percent}% — ${Math.ceil(
              remainingSeconds,
            )} sec remaining`,
          );

          if (socialPostCreateButton) {
            const uploadText = `⏳ Uploading video... ${percent}%${timeText}`;

            if (socialPostCreateButton.tagName === "INPUT") {
              socialPostCreateButton.value = uploadText;
            } else {
              socialPostCreateButton.innerHTML = uploadText;
            }
          }
        });

        // SERVER RESPONSE
        xhr.addEventListener("load", () => {
          console.log("SERVER STATUS:", xhr.status);

          resolve({
            ok: xhr.status >= 200 && xhr.status < 300,
            status: xhr.status,
            text: () => Promise.resolve(xhr.responseText),
          });
        });

        xhr.addEventListener("error", () => {
          reject(new Error("Network error while uploading the post."));
        });

        xhr.addEventListener("abort", () => {
          reject(new Error("Upload was cancelled."));
        });

        xhr.send(formData);
      });

      const responseText = await response.text();

      console.log("SERVER RESPONSE:", responseText);

      let data;

      try {
        data = JSON.parse(responseText);
      } catch (jsonError) {
        throw new Error(
          `Server returned an invalid response (${response.status}).`,
        );
      }

      console.log("CREATE POST RESPONSE:", data);

      if (!response.ok || !data.success) {
        throw new Error(
          data.error ||
            `Unable to create post. Server returned ${response.status}.`,
        );
      }

      if (!data.postId) {
        throw new Error("Post created but postId is missing.");
      }

      const postUrl = `/social/post?postId=${encodeURIComponent(
        String(data.postId),
      )}`;

      console.log("POST CREATED:", data.postId);

      console.log("REDIRECTING TO:", postUrl);

      window.location.assign(postUrl);
    } catch (error) {
      console.error("CREATE SOCIAL POST ERROR:", error);

      alert(error.message || "Unable to create post.");

      // Allow another attempt.
      socialPostIsSubmitting = false;

      socialSetPostButtonState(false);
    }
  });
}

function socialSetAverageImageRatio() {
  const mediaContainers = document.querySelectorAll(".social-post-media");

  mediaContainers.forEach((container) => {
    const images = Array.from(container.querySelectorAll(".social-post-image"));

    // 1 image = leave it as it is
    if (images.length <= 1) {
      return;
    }

    const ratios = images
      .filter((image) => image.naturalWidth > 0 && image.naturalHeight > 0)
      .map((image) => image.naturalWidth / image.naturalHeight);

    if (!ratios.length) {
      return;
    }

    const averageRatio =
      ratios.reduce((total, ratio) => total + ratio, 0) / ratios.length;

    container.style.setProperty("--social-average-image-ratio", averageRatio);
  });
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".social-post-image").forEach((image) => {
    if (image.complete) {
      socialSetAverageImageRatio();
    } else {
      image.addEventListener("load", socialSetAverageImageRatio, {
        once: true,
      });
    }
  });
});

document.addEventListener("click", (event) => {
  const button = event.target.closest(".social-reply-button");

  if (!button) {
    return;
  }

  const commentId = button.dataset.commentId;

  const parentReplyId = button.dataset.parentReplyId || null;

  socialShowReply(commentId, parentReplyId);
});
