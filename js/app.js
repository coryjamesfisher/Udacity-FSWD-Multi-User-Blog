document.addEventListener("DOMContentLoaded", function (event) {

    /* Like Handling */
    (function likeClosure() {
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
    })();
    /* End Like Handling */

    /* Comment Handling */

    (function commentEditClosure(){
        var submitEdit = function(event) {

            var element = event.target,
                content = element.previousSibling.value,
                commentKey = element.parentNode.parentNode.getAttribute("data-comment-key");

            var xmlhttp = new XMLHttpRequest();
            xmlhttp.onreadystatechange = function () {

                // Capture target in closure
                var element = event.target;

                if (xmlhttp.readyState == XMLHttpRequest.DONE) {

                    var response = JSON.parse(xmlhttp.responseText);

                    // If response not success alert
                    if (!response || !response.hasOwnProperty("success") || response.success == false) {
                        alert("Failed to edit comment.");
                    } else {

                        // Find the display for the comment and update it with the new value
                        for (var i in element.parentNode.parentNode.childNodes) {
                            if (element.parentNode.parentNode.childNodes[i].className == "comment-content") {
                                element.parentNode.parentNode.childNodes[i].textContent = content;
                            }
                        }

                        element.parentNode.parentNode.removeChild(element.parentNode);
                    }
                }
            };

            xmlhttp.open("POST", "/comment", true);
            xmlhttp.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
            xmlhttp.send("comment=" + commentKey + "&content=" + content);
        };

        var toggleEdit = function(event) {

            var element = event.target;

            // Comment area already visible the hide it.
            if (element.parentNode.lastChild &&
                element.parentNode.lastChild.className == "edit-comment-form" &&
                element.parentNode.lastChild.style.display != "none") {
                element.parentNode.lastChild.style.display = "none";
            } else {

                // Create comment editing area if it doesn't exist.
                if (element.parentNode.lastChild.className != "edit-comment-form") {
                    var div = document.createElement('div'),
                        textArea = document.createElement("textarea"),
                        button = document.createElement("button"),
                        buttonText = document.createTextNode("text");

                    buttonText.textContent = "Submit";
                    button.appendChild(buttonText);
                    button.addEventListener("click", submitEdit);

                    textArea.style.width = "100%";
                    textArea.value = element.previousSibling.previousSibling.innerHTML;

                    div.className = "edit-comment-form";
                    div.appendChild(textArea);
                    div.appendChild(button);
                    element.parentNode.appendChild(div);
                }

                // Show the comment form.
                element.parentNode.lastChild.style.display = "block";
            }
        };

        // Listen to edit trigger clicks.
        var editTriggers = document.getElementsByClassName('edit-comment-trigger');
        for (i = 0; i < editTriggers.length; i++) {
            editTriggers[i].addEventListener('click', toggleEdit);
        }
    })();

    (function commentClosure(){
        var deleteComment = function(event) {
            var xmlhttp = new XMLHttpRequest();
            xmlhttp.onreadystatechange = function () {

                // Capture target in closure
                var element = event.target;

                if (xmlhttp.readyState == XMLHttpRequest.DONE) {

                    var response = JSON.parse(xmlhttp.responseText);

                    // If response was not success flip the indicator back.
                    if (!response || !response.hasOwnProperty("success") || response.success == false) {
                        alert("Failed to delete comment.");
                    } else {
                        element.parentNode.parentNode.removeChild(element.parentNode);
                    }
                }
            };

            xmlhttp.open("DELETE", "/comment?comment_key=" + event.target.parentNode.getAttribute("data-comment-key"), true);
            xmlhttp.send();
        };

        // Listen for delete trigger clicks.
        var deleteTriggers = document.getElementsByClassName('delete-comment-trigger');
        for (i = 0; i < deleteTriggers.length; i++) {
            deleteTriggers[i].addEventListener('click', deleteComment);
        }
    })();

    /* End Comment Handling */
});