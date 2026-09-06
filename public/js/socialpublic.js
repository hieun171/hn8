function socialPublicSetPostImageRatio(post) {
  if (!post) {
    return;
  }

  const mediaContainer = post.querySelector(".social-post-media");

  if (!mediaContainer) {
    return;
  }

  // ============================================================
  // IMAGES ONLY
  // NEVER APPLY IMAGE RATIO TO VIDEO
  // ============================================================

  const images = Array.from(
    mediaContainer.querySelectorAll(".social-post-image"),
  );

  if (images.length <= 1) {
    mediaContainer.style.removeProperty("--social-average-image-ratio");

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

  mediaContainer.style.setProperty(
    "--social-average-image-ratio",
    averageRatio,
  );
}

// ============================================================
// VIDEO THUMBNAIL / PLAY INITIALIZATION
// ============================================================

function socialPublicInitializeVideos(post) {
  if (!post) {
    return;
  }

  const wrappers = post.querySelectorAll(".social-post-video-wrapper");

  wrappers.forEach((wrapper) => {
    const video = wrapper.querySelector(".social-post-video");

    const poster = wrapper.querySelector(".social-post-video-poster");

    if (!video) {
      return;
    }

    // Prevent duplicate event listeners
    if (video.dataset.socialVideoInitialized === "true") {
      return;
    }

    video.dataset.socialVideoInitialized = "true";

    // ----------------------------------------------------------
    // Thumbnail click → play video
    // ----------------------------------------------------------

    if (poster) {
      poster.addEventListener("click", () => {
        video.play().catch((error) => {
          console.error("SOCIAL VIDEO PLAY ERROR:", error);
        });
      });
    }

    // ----------------------------------------------------------
    // Video started → hide thumbnail
    // ----------------------------------------------------------

    video.addEventListener("play", () => {
      wrapper.classList.add("is-playing");
    });

    // ----------------------------------------------------------
    // Video ended → show thumbnail again
    // ----------------------------------------------------------

    video.addEventListener("ended", () => {
      wrapper.classList.remove("is-playing");
    });

    // ----------------------------------------------------------
    // Video reset to beginning → show thumbnail
    // ----------------------------------------------------------

    video.addEventListener("pause", () => {
      if (video.currentTime === 0) {
        wrapper.classList.remove("is-playing");
      }
    });
  });
}

// ============================================================
// POST INITIALIZATION
// ============================================================

function socialPublicInitializePost(post) {
  if (!post) {
    return;
  }

  // ----------------------------------------------------------
  // IMAGES
  // ----------------------------------------------------------

  const images = post.querySelectorAll(".social-post-image");

  if (images.length) {
    images.forEach((image) => {
      if (image.complete) {
        socialPublicSetPostImageRatio(post);
      } else {
        image.addEventListener(
          "load",
          () => {
            socialPublicSetPostImageRatio(post);
          },
          {
            once: true,
          },
        );
      }
    });
  }

  // ----------------------------------------------------------
  // VIDEOS
  // ----------------------------------------------------------

  socialPublicInitializeVideos(post);
}

// ============================================================
// INITIALIZE ALL POSTS
// ============================================================

function socialPublicInitialize() {
  const posts = document.querySelectorAll(
    ".social-public-page .social-public-post",
  );

  posts.forEach((post) => {
    socialPublicInitializePost(post);
  });
}

// ============================================================
// START
// ============================================================

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", socialPublicInitialize, {
    once: true,
  });
} else {
  socialPublicInitialize();
}
