import { initializeApp } from "firebase/app";
import { GoogleAuthProvider, getAuth, signInWithPopup } from "firebase/auth";

const firebaseConfig = {
  apiKey: "AIzaSyCQWmIVqkwcK6q2tzSXip5PQtGnOe6Qhl4",
  authDomain: "blogs-website-app.firebaseapp.com",
  projectId: "blogs-website-app",
  storageBucket: "blogs-website-app.appspot.com",
  messagingSenderId: "445453101103",
  appId: "1:445453101103:web:874707356244db9cfc7eda",
};

const app = initializeApp(firebaseConfig);

//google auth
const provider = new GoogleAuthProvider();

const auth = getAuth();

export const authWithGoogle = async() => {
  let user = null;
  await signInWithPopup(auth, provider)
    .then((result) => {
        user = result.user;
    })
    .catch((err) => {
      console.log(err);
    });

    return user;
};
