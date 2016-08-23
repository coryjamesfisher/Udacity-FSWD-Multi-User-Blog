document.addEventListener("DOMContentLoaded", function (event) {

    var toggleIndicator = function (element) {

        var likeCountEl = element.nextElementSibling;
        var count = parseInt(likeCountEl.innerHTML);
        if (element.classList.contains('fa-thumbs-up')) {
            element.classList.add('fa-thumbs-o-up');
            element.classList.remove('fa-thumbs-up');
            likeCountEl.innerHTML = count - 1;
        } else {
            element.classList.add('fa-thumbs-up');
            element.classList.remove('fa-thumbs-o-up');
            likeCountEl.innerHTML = count + 1;
        }
    };

    var toggleLike = function (event) {

        // Toggle the indicator in advance. The site will seem faster.
        toggleIndicator(event.target);

        // Send ajax request to record the like.
        var xmlhttp = new XMLHttpRequest();
        xmlhttp.onreadystatechange = function () {

            // Capture target in closure
            var element = event.target;

            if (xmlhttp.readyState == XMLHttpRequest.DONE) {

                var response = JSON.parse(xmlhttp.responseText);

                // If response was not success flip the indicator back.
                if (!response || !response.hasOwnProperty("success") || response.success == false) {
                    toggleIndicator(element);
                }
            }
        };

        xmlhttp.open("POST", "/like?post=" + event.target.getAttribute("data-post"), true);
        xmlhttp.send();
    };

    var likeToggles = document.getElementsByClassName('like-toggle');
    for (var i = 0; i < likeToggles.length; i++) {
        likeToggles[i].addEventListener('click', toggleLike);
    }
});