import React from "react";
import icon from "../Images/icon-w.png";
import Loading from "../Components/Loading";
import axios from "axios";
import { Navigate, Link } from "react-router-dom";
import Cookies from "js-cookie";

class RecoverHOTP extends React.Component {
  constructor(props) {
    super(props);
    this.state = { loading: false };
    this.rc = React.createRef();
    this.password = React.createRef();
    this.email = React.createRef();
    this.submit = this.submit.bind(this);
    this.unremember = this.unremember.bind(this);
  }

  unremember() {
    Cookies.remove('target');
    this.forceUpdate();
  }

  submit(e) {
    e.preventDefault();
    this.setState({ loading: true });
    var qs = "/api/recoverHOTP?email=" + encodeURIComponent(this.email.current.value) +
      "&password=" + encodeURIComponent(this.password.current.value) +
      "&rc=" + encodeURIComponent(this.rc.current.value);

    axios
      .post(qs)
      .then((res) => {
        if (res.data.valid) {
          this.setState({ loading: false, success: true, data: res.data });
        } else {
          this.setState({ loading: false, success: false, data: res.data,
          error: 'One or more factors were incorrect.' });
        }
      })
      .catch((err) => {
        const msg =
          err.response && err.response.data ? err.response.data : err.message;
        this.setState({
          loading: false,
          error: msg,
          emailValid: false,
          nameValid: false,
        });
      });
  }

  render() {
    if (this.state.loading) return <Loading />;
    if (this.state.success) return <Navigate to="/success" />;

    return (<>
      <form action="" onSubmit={this.submit}>
        <div className="mt-3">
          <label htmlFor="email" className="form-label">
            Email address
          </label>
          <input
            type="email"
            className="form-control"
            ref={this.email}
            placeholder="Enter your email"
          />
        </div>
        <div className="mt-3">
          <label htmlFor="email" className="form-label">
            Password
          </label>
          <input
            ref={this.password}
            type="password"
            className="form-control"
            placeholder="Enter your password"
          />
        </div>
        <div className="mt-3">
          <label htmlFor="email" className="form-label">
            Recovery code
          </label>
          <input
            ref={this.rc}
            type="text"
            className="form-control"
            placeholder="Enter your recovery code code"
          />
        </div>
        <button
          className="btn btn-success mt-3 mb-0 w-100"
          type="submit"
        >
          Continue &nbsp;
          <i className="fa fa-arrow-right" />
        </button>
      </form>
      {this.state.error && (
        <div
          className="alert alert-danger mt-3 mb-0"
          role="alert"
        >
          <i className="fa fa-triangle-exclamation"></i>&nbsp;{" "}
          <b>Error: </b>
          {this.state.error}
        </div>
      )}
    </>);
  }
}

export default RecoverHOTP;
