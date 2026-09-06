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

  // One image or no images:
  // remove the average ratio because it is only needed
  // when multiple images are present.
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
// VIDEO INITIALIZATION
//
// Videos use the native HTML <video poster="...">.
//
// NO separate thumbnail <img>
// NO thumbnail click handler
// NO image ratio
// NO forced video aspect ratio
// ============================================================

function socialPublicInitializeVideos(post) {
  if (!post) {
    return;
  }

  const videos = post.querySelectorAll(".social-post-video");

  videos.forEach((video) => {
    // ----------------------------------------------------------
    // Prevent duplicate initialization
    // ----------------------------------------------------------

    if (video.dataset.socialVideoInitialized === "true") {
      return;
    }

    video.dataset.socialVideoInitialized = "true";

    const wrapper = video.closest(".social-post-video-wrapper");

    // ----------------------------------------------------------
    // Video started
    // ----------------------------------------------------------

    video.addEventListener("play", () => {
      if (wrapper) {
        wrapper.classList.add("is-playing");
      }
    });

    // ----------------------------------------------------------
    // Video ended
    // ----------------------------------------------------------

    video.addEventListener("ended", () => {
      if (wrapper) {
        wrapper.classList.remove("is-playing");
      }
    });

    // ----------------------------------------------------------
    // Video paused at the very beginning
    //
    // This is optional, but keeps the wrapper state clean
    // if the user pauses before playback has actually started.
    // ----------------------------------------------------------

    video.addEventListener("pause", () => {
      if (video.currentTime === 0 && wrapper) {
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

  // ============================================================
  // IMAGES
  // ============================================================

  const images = post.querySelectorAll(".social-post-image");

  if (images.length) {
    images.forEach((image) => {
      // --------------------------------------------------------
      // Image already loaded
      // --------------------------------------------------------

      if (image.complete) {
        socialPublicSetPostImageRatio(post);
        return;
      }

      // --------------------------------------------------------
      // Image still loading
      // --------------------------------------------------------

      image.addEventListener(
        "load",
        () => {
          socialPublicSetPostImageRatio(post);
        },
        {
          once: true,
        },
      );
    });
  }

  // ============================================================
  // VIDEOS
  // ============================================================

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
